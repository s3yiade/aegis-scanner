/**
 * Lightweight same-origin check for state-changing routes that don't sit
 * behind the captcha-on-first-hit flow (lead capture, monitor signup).
 * Not a substitute for the captcha/rate-limit/disposable-email checks —
 * Origin/Referer headers are attacker-controllable outside a browser
 * context — but it does raise the bar against simple cross-site form
 * submission and stray browser-based abuse, at zero cost to legitimate
 * same-app requests.
 */
export function isSameOrigin(req: Request): boolean {
  const appUrl = process.env.APP_URL;
  if (!appUrl) return true; // can't verify without a configured app URL — fail open in dev

  let appOrigin: string;
  try {
    appOrigin = new URL(appUrl).origin;
  } catch {
    return true;
  }

  const origin = req.headers.get('origin');
  if (origin) return origin === appOrigin;

  // Some legitimate same-origin requests (e.g. top-level navigations,
  // certain older browsers) omit Origin but include Referer.
  const referer = req.headers.get('referer');
  if (referer) {
    try {
      return new URL(referer).origin === appOrigin;
    } catch {
      return false;
    }
  }

  // Neither header present — reject rather than assume same-origin.
  return false;
}
