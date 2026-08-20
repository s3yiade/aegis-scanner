import sharp from 'sharp';
import { renderPageScreenshot } from './renderPage';

/**
 * Computes a difference hash (dHash) of a screenshot — resize to a tiny
 * grid, compare each pixel to its neighbor, one bit per comparison. Two
 * visually similar pages (even after minor edits, recoloring, or a
 * translated headline) produce hashes with a small Hamming distance,
 * giving a graded similarity score rather than an exact-pixel-match
 * requirement (which would miss almost every real clone, since attackers
 * routinely make small edits).
 *
 * Only ever called from the gated consult/deep-scan flow — screenshotting
 * is a paid rendering-API call per page, same reasoning as renderPage.ts.
 */

const HASH_WIDTH = 9; // 9x8 -> 8x8 = 64 horizontal comparisons = 64-bit hash
const HASH_HEIGHT = 8;

export async function computeDHash(imageBytes: Buffer): Promise<bigint | null> {
  try {
    const { data } = await sharp(imageBytes)
      .resize(HASH_WIDTH, HASH_HEIGHT, { fit: 'fill' })
      .grayscale()
      .raw()
      .toBuffer({ resolveWithObject: true });

    // Guard against a near-blank/uniform image (a common headless-render
    // failure mode: screenshot taken before JS-rendered content loads, a
    // render error returning a blank page, a genuinely all-white loading
    // state) producing a degenerate hash. Two unrelated blank screenshots
    // would otherwise coincidentally land on a near-identical hash and
    // read as "highly similar" purely because there's nothing in either
    // image to actually differentiate — not because the pages are related.
    let min = 255;
    let max = 0;
    for (let i = 0; i < data.length; i++) {
      const v = data[i] ?? 0;
      if (v < min) min = v;
      if (v > max) max = v;
    }
    if (max - min < 10) return null; // effectively a single flat color — not usable

    let hash = 0n;
    let bitIndex = 0n;
    for (let row = 0; row < HASH_HEIGHT; row++) {
      for (let col = 0; col < HASH_WIDTH - 1; col++) {
        const left = data[row * HASH_WIDTH + col] ?? 0;
        const right = data[row * HASH_WIDTH + col + 1] ?? 0;
        if (left > right) hash |= 1n << bitIndex;
        bitIndex++;
      }
    }
    return hash;
  } catch (err) {
    console.error('dHash computation failed', err);
    return null;
  }
}

export function hammingDistance(a: bigint, b: bigint): number {
  let x = a ^ b;
  let count = 0;
  while (x > 0n) {
    count += Number(x & 1n);
    x >>= 1n;
  }
  return count;
}

export interface VisualComparisonResult {
  status: 'complete' | 'skipped_no_api_key' | 'failed';
  similarity: number; // 0-1, only meaningful if status === 'complete'
}

/** Screenshots both URLs and returns their visual similarity (0-1). */
export async function compareScreenshots(targetUrl: string, candidateUrl: string): Promise<VisualComparisonResult> {
  const [targetShot, candidateShot] = await Promise.all([
    renderPageScreenshot(targetUrl),
    renderPageScreenshot(candidateUrl),
  ]);

  if (targetShot.status === 'skipped_no_api_key' || candidateShot.status === 'skipped_no_api_key') {
    return { status: 'skipped_no_api_key', similarity: 0 };
  }
  if (!targetShot.imageBytes || !candidateShot.imageBytes) {
    return { status: 'failed', similarity: 0 };
  }

  const [hashA, hashB] = await Promise.all([
    computeDHash(targetShot.imageBytes),
    computeDHash(candidateShot.imageBytes),
  ]);

  if (hashA === null || hashB === null) return { status: 'failed', similarity: 0 };

  const distance = hammingDistance(hashA, hashB);
  return { status: 'complete', similarity: 1 - distance / 64 };
}
