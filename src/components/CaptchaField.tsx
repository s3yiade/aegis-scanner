'use client';

import TurnstileWidget from '@/components/TurnstileWidget';
import type { UseCaptchaResult } from '@/hooks/useCaptcha';

export default function CaptchaField({ captcha, isAdmin }: { captcha: UseCaptchaResult; isAdmin: boolean }) {
  if (isAdmin) return null;

  if (captcha.provider === 'turnstile') {
    if (!captcha.siteKey) return null;
    return (
      <div className="captcha-row">
        <TurnstileWidget siteKey={captcha.siteKey} onToken={captcha.setTurnstileToken} onExpire={() => captcha.setTurnstileToken(null)} />
      </div>
    );
  }

  if (captcha.provider === 'self' && captcha.challenge) {
    return (
      <div className="captcha-row">
        <span>{captcha.challenge.question}</span>
        <input
          type="number"
          placeholder="Answer"
          value={captcha.answer}
          onChange={(e) => captcha.setAnswer(e.target.value)}
          required
        />
        {captcha.solvingPow && (
          <span className="muted" style={{ fontSize: '0.75rem' }}>
            verifying…
          </span>
        )}
      </div>
    );
  }

  return null;
}
