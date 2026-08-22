import fs from 'node:fs';
import path from 'node:path';
import { PDFDocument, StandardFonts, rgb, PageSizes, type PDFFont, type PDFPage } from 'pdf-lib';
import type { ScanResult } from '@/types/scan';
import { groupByCategory } from '@/lib/scanner/categories';
import { summarizeCompliance, FRAMEWORK_META, COMPLIANCE_DISCLAIMER } from '@/lib/scanner/compliance';

const SEVERITY_COLOR: Record<string, [number, number, number]> = {
  critical: [0.8, 0.15, 0.15],
  high: [0.85, 0.4, 0.1],
  medium: [0.85, 0.65, 0.1],
  low: [0.3, 0.5, 0.85],
  info: [0.5, 0.5, 0.5],
  pass: [0.15, 0.6, 0.3],
};

const GRADE_COLOR: Record<string, [number, number, number]> = {
  A: [0.15, 0.6, 0.3],
  B: [0.4, 0.6, 0.2],
  C: [0.85, 0.65, 0.1],
  D: [0.85, 0.4, 0.1],
  F: [0.8, 0.15, 0.15],
};

const INK = [0.1, 0.1, 0.1] as [number, number, number];
const MUTED = [0.45, 0.45, 0.5] as [number, number, number];
const HEADING = [0.1, 0.15, 0.3] as [number, number, number];
const RULE = [0.85, 0.85, 0.88] as [number, number, number];

export interface PdfReportExtras {
  targetType: 'web' | 'api';
  nicheCopy?: { label: string; whyItMatters: string } | null;
  endpointCopy?: { label: string; whyItMatters: string } | null;
  benchmark?: { avgScore: number; avgGrade: string; sampleSize: number } | null;
}

/**
 * Renders a branded, sectioned PDF of the full report (no external
 * rendering service needed) — mirrors the structure of the report page
 * itself (score -> why-it-matters -> issues -> passing checks -> compliance
 * mapping -> disclaimers) so the two never drift into showing different
 * information, and adds the logo, a footer with page numbers, and an
 * expanded disclaimers section a bare findings dump didn't have.
 */
export async function renderReportPdf(
  result: ScanResult,
  appName = 'Aegis',
  extras: PdfReportExtras = { targetType: result.targetType }
): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const logoImage = await embedLogo(pdf);

  const margin = 50;
  const pageSize = PageSizes.A4;
  const [pageWidth, pageHeight] = pageSize;
  const contentWidth = pageWidth - margin * 2;

  let page = pdf.addPage(pageSize);
  let y = pageHeight - margin;

  const ensureSpace = (needed: number) => {
    if (y - needed < margin + 30) {
      page = pdf.addPage(pageSize);
      y = pageHeight - margin;
    }
  };

  const drawText = (text: string, opts: { size?: number; f?: PDFFont; color?: [number, number, number]; x?: number } = {}) => {
    const size = opts.size ?? 11;
    ensureSpace(size + 4);
    page.drawText(text, { x: opts.x ?? margin, y, size, font: opts.f ?? font, color: rgb(...(opts.color ?? INK)) });
    y -= size + 8;
  };

  const drawDivider = () => {
    ensureSpace(14);
    y -= 4;
    page.drawLine({ start: { x: margin, y }, end: { x: pageWidth - margin, y }, thickness: 0.75, color: rgb(...RULE) });
    y -= 12;
  };

  const drawSectionHeading = (title: string) => {
    ensureSpace(30);
    y -= 6;
    page.drawRectangle({ x: margin, y: y - 2, width: 4, height: 16, color: rgb(...HEADING) });
    page.drawText(title, { x: margin + 12, y, size: 14, font: bold, color: rgb(...HEADING) });
    y -= 22;
  };

  // --- Header: logo + name + target meta + score panel ---
  if (logoImage) {
    const logoHeight = 32;
    const logoWidth = (logoImage.width / logoImage.height) * logoHeight;
    page.drawImage(logoImage, { x: margin, y: y - logoHeight + 6, width: logoWidth, height: logoHeight });
    page.drawText(appName, { x: margin + logoWidth + 12, y: y - 12, size: 20, font: bold, color: rgb(...HEADING) });
    y -= logoHeight + 10;
  } else {
    drawText(appName, { size: 20, f: bold, color: HEADING });
  }
  drawText('Security Scan Report', { size: 13, f: bold, color: MUTED });
  y -= 2;

  drawText(`Target: ${result.hostname}  (${extras.targetType === 'api' ? 'API / SaaS endpoint' : 'Website / web app'})`, { size: 11 });
  drawText(`Scanned: ${new Date(result.scannedAt).toLocaleString()}`, { size: 11, color: MUTED });

  // Score panel
  ensureSpace(56);
  const gradeColor = GRADE_COLOR[result.grade] ?? INK;
  page.drawRectangle({ x: margin, y: y - 48, width: contentWidth, height: 48, color: rgb(...gradeColor), opacity: 0.08 });
  page.drawRectangle({ x: margin, y: y - 48, width: 6, height: 48, color: rgb(...gradeColor) });
  page.drawText(result.grade, { x: margin + 20, y: y - 34, size: 30, font: bold, color: rgb(...gradeColor) });
  page.drawText(`${result.score} / 100`, { x: margin + 70, y: y - 20, size: 13, font: bold, color: rgb(...INK) });
  page.drawText('Overall security grade', { x: margin + 70, y: y - 38, size: 9, font, color: rgb(...MUTED) });
  y -= 62;

  if (extras.nicheCopy) {
    drawWrapped(`Why this matters for ${extras.nicheCopy.label.toLowerCase()}: ${extras.nicheCopy.whyItMatters}`, {
      drawText,
      size: 10,
      color: MUTED,
      maxChars: 100,
    });
  }
  if (extras.endpointCopy) {
    drawWrapped(`Why this matters for a ${extras.endpointCopy.label.toLowerCase()}: ${extras.endpointCopy.whyItMatters}`, {
      drawText,
      size: 10,
      color: MUTED,
      maxChars: 100,
    });
  }
  if (extras.benchmark) {
    drawText(
      `Businesses in this category average a ${extras.benchmark.avgGrade} (${Math.round(extras.benchmark.avgScore)}/100) across ${extras.benchmark.sampleSize} scans.`,
      { size: 10, color: MUTED }
    );
  }

  drawDivider();

  // --- Issues found / Passing checks — same grouping as the report page ---
  const severityRank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, pass: 0 };
  const failed = result.findings.filter((f) => !f.passed);
  const passed = result.findings.filter((f) => f.passed);

  if (failed.length > 0) {
    drawSectionHeading(`Issues Found (${failed.length})`);
    for (const group of groupByCategory(failed)) {
      drawText(group.label, { size: 11.5, f: bold, color: HEADING });
      const ordered = [...group.findings].sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0));
      for (const finding of ordered) {
        const color = SEVERITY_COLOR[finding.severity] ?? INK;
        drawText(`[${finding.severity.toUpperCase()}] ${finding.title}`, { size: 10.5, x: margin + 4, color });
        for (const line of wrapLines(finding.detail, 92)) {
          drawText(line, { size: 9, x: margin + 4, color: MUTED });
        }
        if (!finding.passed) {
          const recLines = wrapLines(finding.recommendation, 88);
          recLines.forEach((line, i) => drawText(i === 0 ? `Fix: ${line}` : line, { size: 9, x: margin + 4, color: INK }));
        }
      }
      y -= 4;
    }
    drawDivider();
  }

  if (passed.length > 0) {
    drawSectionHeading(`Passing Checks (${passed.length})`);
    for (const group of groupByCategory(passed)) {
      drawText(group.label, { size: 11.5, f: bold, color: HEADING });
      for (const finding of group.findings) {
        ensureSpace(16);
        page.drawText(`OK  ${finding.title}`, { x: margin + 4, y, size: 9.5, font, color: rgb(...(SEVERITY_COLOR.pass ?? INK)) });
        y -= 14;
      }
      y -= 4;
    }
    drawDivider();
  }

  // --- Compliance framework mapping ---
  const compliance = summarizeCompliance(result.findings);
  const frameworksTouched = (Object.keys(compliance) as (keyof typeof compliance)[]).filter((fw) => compliance[fw].length > 0);

  if (frameworksTouched.length > 0) {
    drawSectionHeading('Compliance Framework Mapping');
    drawDisclaimerBox(COMPLIANCE_DISCLAIMER, {
      margin,
      contentWidth,
      font,
      ensureSpace,
      getPage: () => page,
      getY: () => y,
      setY: (v) => (y = v),
    });

    for (const fw of frameworksTouched) {
      const controls = compliance[fw];
      const gaps = controls.filter((c) => c.status === 'gap');
      drawText(`${FRAMEWORK_META[fw].label} - ${gaps.length} of ${controls.length} touched control(s) flagged for review`, {
        size: 10.5,
        f: bold,
        color: HEADING,
      });
      for (const c of controls) {
        ensureSpace(14);
        const color = (c.status === 'gap' ? SEVERITY_COLOR.medium : SEVERITY_COLOR.pass) ?? INK;
        page.drawText(`${c.status === 'gap' ? '!' : 'OK'} ${c.controlId} - ${c.controlTitle}`, {
          x: margin + 4,
          y,
          size: 9,
          font,
          color: rgb(...color),
        });
        y -= 13;
      }
      y -= 6;
    }
    drawDivider();
  }

  // --- Disclaimers ---
  drawSectionHeading('Important Disclaimers');
  const disclaimerText =
    'This report is the output of an automated, passive security scan performed at the date/time listed above. It reflects only ' +
    'what was externally observable at that moment, checks a bounded set of common misconfigurations, and does not attempt any ' +
    'exploitation. Absence of a finding is not a guarantee of security, and this is not a penetration test, source code audit, ' +
    `or compliance certification of any kind. Nothing in this report constitutes legal, security, or compliance advice. ${appName} ` +
    'makes no warranty as to the completeness or fitness of this report for any particular purpose. For a comprehensive assessment, ' +
    'engage a qualified security professional or, for compliance needs specifically, a qualified auditor/assessor for that framework.';
  drawDisclaimerBox(disclaimerText, {
    margin,
    contentWidth,
    font,
    ensureSpace,
    getPage: () => page,
    getY: () => y,
    setY: (v) => (y = v),
  });

  // --- Footer on every page (page numbers require a second pass) ---
  const pages = pdf.getPages();
  const generatedOn = new Date().toLocaleDateString();
  pages.forEach((p, i) => {
    p.drawText(`${appName} | ${result.hostname} | Page ${i + 1} of ${pages.length} | Generated ${generatedOn}`, {
      x: margin,
      y: 24,
      size: 8,
      font,
      color: rgb(...MUTED),
    });
  });

  return pdf.save();
}

async function embedLogo(pdf: PDFDocument) {
  try {
    const logoPath = path.join(process.cwd(), 'public', 'aegis_upscaled.png');
    const bytes = fs.readFileSync(logoPath);
    return await pdf.embedPng(bytes);
  } catch {
    // Missing/unreadable asset shouldn't ever fail report generation —
    // the header just falls back to text-only (see renderReportPdf).
    return null;
  }
}

function drawWrapped(
  text: string,
  opts: {
    drawText: (t: string, o?: { size?: number; f?: PDFFont; color?: [number, number, number] }) => void;
    size: number;
    color: [number, number, number];
    maxChars: number;
  }
) {
  for (const line of wrapLines(text, opts.maxChars)) {
    opts.drawText(line, { size: opts.size, color: opts.color });
  }
}

/** Boxed disclaimer callout — visually distinct (border + light background)
 * so it reads as "read this separately," not just another paragraph.
 * Takes getPage()/getY()/setY() rather than plain values: ensureSpace can
 * trigger a page break partway through (reassigning the caller's `page`
 * and `y` closures before this runs), so a plain captured page/y argument
 * would go stale the moment that happens — these getters always read the
 * current values instead. */
function drawDisclaimerBox(
  text: string,
  ctx: {
    margin: number;
    contentWidth: number;
    font: PDFFont;
    ensureSpace: (n: number) => void;
    getPage: () => PDFPage;
    getY: () => number;
    setY: (v: number) => void;
  }
): void {
  const lines = wrapLines(text, 100);
  const lineHeight = 12;
  const boxHeight = lines.length * lineHeight + 16;

  ctx.ensureSpace(boxHeight + 10);
  const page = ctx.getPage();
  const y = ctx.getY();

  page.drawRectangle({
    x: ctx.margin,
    y: y - boxHeight,
    width: ctx.contentWidth,
    height: boxHeight,
    color: rgb(0.95, 0.95, 0.97),
    borderColor: rgb(...RULE),
    borderWidth: 1,
  });

  let ly = y - 12;
  for (const line of lines) {
    page.drawText(line, { x: ctx.margin + 10, y: ly, size: 8.5, font: ctx.font, color: rgb(...MUTED) });
    ly -= lineHeight;
  }
  ctx.setY(y - boxHeight - 14);
}

/** Simple greedy word-wrap by character count (pdf-lib doesn't measure or
 * wrap text for us, and this app doesn't pull in a layout engine for one
 * report). Splits on whitespace only — a single "word" longer than
 * maxChars is left on its own line rather than hard-broken mid-word, which
 * is an acceptable tradeoff for report prose (URLs, mainly) vs. the
 * complexity of grapheme-aware breaking. */
function wrapLines(text: string, maxChars: number): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length > maxChars && current) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(current);
  return lines.length ? lines : [''];
}
