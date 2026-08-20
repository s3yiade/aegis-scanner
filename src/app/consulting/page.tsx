'use client';

import { useEffect, useState } from 'react';
import TopNav from '@/components/TopNav';
import SiteFooter from '@/components/SiteFooter';
import { useCaptcha } from '@/hooks/useCaptcha';
import CaptchaField from '@/components/CaptchaField';
import { useIsAdmin } from '@/hooks/useIsAdmin';

export default function ConsultingPage() {
  const { isAdmin, adminEmail } = useIsAdmin();
  const captcha = useCaptcha();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [status, setStatus] = useState<'idle' | 'submitting' | 'done' | 'error'>('idle');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isAdmin && adminEmail) setEmail((prev) => prev || adminEmail);
  }, [isAdmin, adminEmail]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus('submitting');
    setError(null);
    try {
      const res = await fetch('/api/consult', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          name: name || undefined,
          message: message || undefined,
          requestType: 'general',
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Something went wrong.');
        captcha.reload();
        setStatus('error');
        return;
      }
      setStatus('done');
    } catch {
      setError('Network error — please try again.');
      setStatus('error');
    }
  }

  return (
    <div className="container">
      <TopNav active="/consulting" />

      <div className="eyebrow">
        <span className="dot" />
        Scan → fix → verify
      </div>

      <div className="hero">
        <h1>Security scanning, plus someone who actually fixes it</h1>
        <p>
          Most scanners stop at a list of findings. Aegis is built by the same people who&apos;ll implement the fix —
          the report isn&apos;t the end of the engagement, it&apos;s the start of one.
        </p>
      </div>

      <div className="module-grid">
        <div className="module-card">
          <div className="icon">◈</div>
          <h4>What Aegis scans</h4>
          <p>
            Free, instant, and passive (no exploitation attempts) — headers, TLS configuration, DNS mail-spoofing
            protection (SPF/DMARC), and commonly exposed files, on the Web Scans and SaaS Scans tabs. The SaaS scan
            adds CORS, GraphQL introspection, exposed API docs, client-side secrets, source maps, and SRI checks.
          </p>
        </div>

        <div className="module-card">
          <div className="icon">⌁</div>
          <h4>Domain clone &amp; phishing protection</h4>
          <p>
            Every scan checks for lookalike domains registered against your brand — including ones registered but
            not yet activated. Paid options add the full domain list, a deeper similarity analysis, and an ongoing
            watch that alerts you the moment a dormant lookalike goes live.
          </p>
        </div>

        <div className="module-card">
          <div className="icon">▤</div>
          <h4>Fix-it-yourself guides</h4>
          <p>
            Every finding comes with a one-line recommendation for free. The paid unlock adds a full step-by-step
            procedure — exact commands, config snippets, and what to verify afterward.
          </p>
        </div>

        <div className="module-card">
          <div className="icon">✓</div>
          <h4>Consulting — we do the fixing</h4>
          <p>
            Web application security audits and Linux server hardening, done directly by us. A scan tells you
            what&apos;s wrong; a consult fixes it. Typical engagements: a one-time hardening pass, ongoing monthly
            re-checks, or an as-needed retainer.
          </p>
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Get in touch</h3>
        {status === 'done' ? (
          <p>Thanks — we&apos;ll be in touch shortly.</p>
        ) : (
          <form onSubmit={handleSubmit}>
            <label htmlFor="consult-name">Name</label>
            <input id="consult-name" type="text" maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
            <label htmlFor="consult-email">Email</label>
            <input
              id="consult-email"
              type="email"
              required
              maxLength={320}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@business.com"
            />
            <label htmlFor="consult-message">What can we help with?</label>
            <input id="consult-message" type="text" maxLength={1000} value={message} onChange={(e) => setMessage(e.target.value)} />

            <CaptchaField captcha={captcha} isAdmin={isAdmin} />

            {error && <div className="error">{error}</div>}

            <button type="submit" disabled={status === 'submitting'}>
              {status === 'submitting' ? 'Sending…' : 'Send'}
            </button>
          </form>
        )}
      </div>

      <SiteFooter />
    </div>
  );
}
