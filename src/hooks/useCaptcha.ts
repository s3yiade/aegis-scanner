'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

export interface CaptchaPayload {
  selfToken?: string;
  selfAnswer?: number;
  selfPowNonce?: string;
  turnstileToken?: string;
}

interface SelfChallengeState {
  question: string;
  token: string;
  powDifficulty: number;
}

function hasLeadingZeroBits(bytes: Uint8Array, bits: number): boolean {
  let remaining = bits;
  for (const byte of bytes) {
    if (remaining <= 0) break;
    if (remaining >= 8) {
      if (byte !== 0) return false;
      remaining -= 8;
    } else {
      if (byte >> (8 - remaining) !== 0) return false;
      remaining = 0;
    }
  }
  return true;
}

/** Brute-forces a nonce so sha256(`${token}:${nonce}`) has `difficulty`
 * leading zero bits. At difficulty 14 this is a few thousand hashes on
 * average — imperceptible on a real device, but it means answering a
 * captcha costs real client-side compute rather than one free HTTP call
 * per guess. Yields back to the event loop periodically so it never
 * visibly blocks the UI. */
async function solveProofOfWork(token: string, difficulty: number, signal: { cancelled: boolean }): Promise<string | null> {
  const encoder = new TextEncoder();
  let nonce = 0;
  while (!signal.cancelled) {
    const data = encoder.encode(`${token}:${nonce}`);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    if (hasLeadingZeroBits(digest, difficulty)) return String(nonce);
    nonce++;
    if (nonce % 3000 === 0) await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return null;
}

export function useCaptcha() {
  const [provider, setProvider] = useState<'self' | 'turnstile' | null>(null);
  const [siteKey, setSiteKey] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<SelfChallengeState | null>(null);
  const [answer, setAnswer] = useState('');
  const [powNonce, setPowNonce] = useState<string | null>(null);
  const [solvingPow, setSolvingPow] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const cancelRef = useRef({ cancelled: false });

  const load = useCallback(async () => {
    cancelRef.current.cancelled = true; // stop any in-flight PoW solve from a previous challenge
    const signal = { cancelled: false };
    cancelRef.current = signal;

    setTurnstileToken(null);
    setPowNonce(null);
    setAnswer('');
    setChallenge(null);

    try {
      const res = await fetch('/api/captcha');
      const data = await res.json();
      if (signal.cancelled) return;
      setProvider(data.provider);
      if (data.provider === 'self') {
        setChallenge({ question: data.question, token: data.token, powDifficulty: data.powDifficulty });
        setSolvingPow(true);
        const nonce = await solveProofOfWork(data.token, data.powDifficulty, signal);
        if (signal.cancelled) return;
        setPowNonce(nonce);
        setSolvingPow(false);
      } else {
        setSiteKey(data.siteKey ?? null);
      }
    } catch {
      if (!signal.cancelled) setProvider(null);
    }
  }, []);

  useEffect(() => {
    load();
    return () => {
      cancelRef.current.cancelled = true;
    };
  }, [load]);

  const payload: CaptchaPayload =
    provider === 'turnstile'
      ? { turnstileToken: turnstileToken ?? undefined }
      : challenge
        ? { selfToken: challenge.token, selfAnswer: answer === '' ? undefined : Number(answer), selfPowNonce: powNonce ?? undefined }
        : {};

  const ready =
    provider === 'turnstile'
      ? Boolean(turnstileToken)
      : Boolean(challenge && answer !== '' && powNonce && !solvingPow);

  return {
    provider,
    siteKey,
    challenge,
    answer,
    setAnswer,
    solvingPow,
    turnstileToken,
    setTurnstileToken,
    payload,
    ready,
    reload: load,
  };
}

export type UseCaptchaResult = ReturnType<typeof useCaptcha>;
