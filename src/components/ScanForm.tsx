'use client';

import { useEffect, useState } from 'react';
import type { TeaserResult } from '@/types/scan';
import { useCaptcha } from '@/hooks/useCaptcha';
import CaptchaField from '@/components/CaptchaField';
import { useIsAdmin } from '@/hooks/useIsAdmin';
import { useIdleTimeout } from '@/hooks/useIdleTimeout';
import { IDLE_TIMEOUT_MS } from '@/lib/idleConfig';

const NICHES = [
  { value: 'jewelry', label: 'Jewelry / high-value retail' },
  { value: 'ecommerce', label: 'E-commerce' },
  { value: 'professional_services', label: 'Professional services' },
  { value: 'healthcare', label: 'Healthcare / clinic' },
  { value: 'contractor_trades', label: 'Contractor / trades' },
  { value: 'restaurant_hospitality', label: 'Restaurant / hospitality' },
];

const URL_MAX_LEN = 300;

function sanitizeUrlInput(raw: string): string {
  const singleLine = raw.replace(/[\r\n]+/g, '').replace(/[\x00-\x1F\x7F]/g, '');
  return singleLine.slice(0, URL_MAX_LEN);
}

function FunnelSteps({ current }: { current: 1 | 2 }) {
  return (
    <div className="funnel-steps">
      <div className={`funnel-step ${current === 1 ? 'active' : 'done'}`}>
        <span className="funnel-step-dot">{current === 1 ? '1' : '✓'}</span>
        Scan
      </div>
      <div className={`funnel-connector ${current === 2 ? 'done' : ''}`} />
      <div className={`funnel-step ${current === 2 ? 'active' : ''}`}>
        <span className="funnel-step-dot">2</span>
        Unlock
      </div>
      <div className="funnel-connector" />
      <div className="funnel-step">
        <span className="funnel-step-dot">3</span>
        Report
      </div>
    </div>
  );
}

export interface ScanFormProps {
  defaultTargetType: 'web' | 'api';
  heading: string;
  subheading: string;
  storageKeyPrefix: string; // keeps Web/SaaS tab persistence separate
}

export default function ScanForm({ defaultTargetType, heading, subheading, storageKeyPrefix }: ScanFormProps) {
  const [url, setUrl] = useState('');
  const [targetType, setTargetType] = useState<'web' | 'api'>(defaultTargetType);
  const [niche, setNiche] = useState('');
  const [ownershipConfirmed, setOwnershipConfirmed] = useState(false);
  const captcha = useCaptcha();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [teaser, setTeaser] = useState<TeaserResult | null>(null);
  const { isAdmin } = useIsAdmin();

  // Privacy measure for a shared/unattended screen — clears the URL/niche
  // fields (never anything already submitted/stored) after a few minutes
  // of inactivity. See lib/idleConfig.
  useIdleTimeout(IDLE_TIMEOUT_MS, () => {
    setUrl('');
    setNiche('');
  });

  useEffect(() => {
    try {
      const lastUrl = window.localStorage.getItem(`${storageKeyPrefix}:lastUrl`);
      const lastNiche = window.localStorage.getItem(`${storageKeyPrefix}:lastNiche`);
      if (lastUrl) setUrl(lastUrl);
      if (lastNiche) setNiche(lastNiche);
    } catch {
      // localStorage unavailable — fine, just skip persistence
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(`${storageKeyPrefix}:lastUrl`, url);
    } catch {
      // ignore
    }
  }, [url, storageKeyPrefix]);

  useEffect(() => {
    try {
      window.localStorage.setItem(`${storageKeyPrefix}:lastNiche`, niche);
    } catch {
      // ignore
    }
  }, [niche, storageKeyPrefix]);

  function handleUrlChange(e: React.ChangeEvent<HTMLInputElement>) {
    setUrl(sanitizeUrlInput(e.target.value));
  }

  function handleUrlPaste(e: React.ClipboardEvent<HTMLInputElement>) {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text');
    setUrl(sanitizeUrlInput(pasted));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!isAdmin && !ownershipConfirmed) {
      setError('Please confirm you own or are authorized to scan this target.');
      return;
    }

    setLoading(true);
    setTeaser(null);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          targetType,
          niche: niche || null,
          ownershipConfirmed: true,
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Something went wrong.');
        captcha.reload();
        return;
      }
      setTeaser(data);
    } catch {
      setError('Network error — please try again.');
    } finally {
      setLoading(false);
    }
  }

  if (teaser) {
    return <ResultTeaser teaser={teaser} onReset={() => setTeaser(null)} />;
  }

  return (
    <>
      <FunnelSteps current={1} />

      <div className="hero">
        <h1>{heading}</h1>
        <p>{subheading}</p>
      </div>

      <form className="card" onSubmit={handleSubmit}>
        <label htmlFor="url">Website or API URL</label>
        <input
          id="url"
          type="text"
          placeholder="example.com"
          value={url}
          onChange={handleUrlChange}
          onPaste={handleUrlPaste}
          maxLength={URL_MAX_LEN}
          spellCheck={false}
          autoComplete="off"
          required
        />

        <label htmlFor="targetType">What are we scanning?</label>
        <select id="targetType" value={targetType} onChange={(e) => setTargetType(e.target.value as 'web' | 'api')}>
          <option value="web">Website / web app</option>
          <option value="api">API endpoint / backend</option>
        </select>

        <label htmlFor="niche">Business type (optional — tailors the results)</label>
        <select id="niche" value={niche} onChange={(e) => setNiche(e.target.value)}>
          <option value="">Prefer not to say</option>
          {NICHES.map((n) => (
            <option key={n.value} value={n.value}>
              {n.label}
            </option>
          ))}
        </select>

        {!isAdmin && (
          <label className="checkbox-row" htmlFor="ownership">
            <input
              id="ownership"
              type="checkbox"
              checked={ownershipConfirmed}
              onChange={(e) => setOwnershipConfirmed(e.target.checked)}
            />
            <span>I own this website/app, or I have explicit authorization from the owner to scan it.</span>
          </label>
        )}

        <CaptchaField captcha={captcha} isAdmin={isAdmin} />

        {error && <div className="error">{error}</div>}

        <button type="submit" disabled={loading}>
          {loading ? 'Scanning…' : 'Run free scan'}
        </button>
      </form>

      <p className="muted" style={{ fontSize: '0.85rem' }}>
        We only run passive, read-only checks — no exploitation attempts. Limited to 5 scans/hour and 20/day per
        visitor.
      </p>
    </>
  );
}

function ResultTeaser({ teaser, onReset }: { teaser: TeaserResult; onReset: () => void }) {
  const { isAdmin, adminEmail } = useIsAdmin();
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const captcha = useCaptcha();
  const [submitting, setSubmitting] = useState(false);
  const [unlocked, setUnlocked] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isAdmin && adminEmail) setEmail((prev) => prev || adminEmail);
  }, [isAdmin, adminEmail]);

  // Same idle-clear privacy measure as the scan form above.
  useIdleTimeout(IDLE_TIMEOUT_MS, () => {
    setEmail('');
    setName('');
  });

  const color =
    teaser.grade === 'A' ? 'var(--pass)' : teaser.grade === 'B' ? 'var(--low)' : teaser.grade === 'C' ? 'var(--medium)' : teaser.grade === 'D' ? 'var(--high)' : 'var(--critical)';

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/lead', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId: teaser.scanId,
          email,
          name: name || undefined,
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Something went wrong.');
        captcha.reload();
        return;
      }
      setUnlocked(true);
      window.location.href = `/report/${teaser.scanId}`;
    } catch {
      setError('Network error — please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <FunnelSteps current={2} />
      <div className="card">
      <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 16 }}>
        <div className="score-badge" style={{ borderColor: color, color }}>
          {teaser.grade}
        </div>
        <div>
          <div style={{ fontSize: '1.3rem', fontWeight: 700 }}>{teaser.hostname}</div>
          <div className="muted">
            Score: {teaser.score}/100 — {teaser.headline}
          </div>
        </div>
      </div>

      <p className="muted">Enter your email to unlock the full report with specific findings and fixes.</p>

      {!unlocked ? (
        <form onSubmit={handleUnlock}>
          <label htmlFor="name">Name (optional)</label>
          <input id="name" type="text" maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            required
            maxLength={320}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@business.com"
          />
          <CaptchaField captcha={captcha} isAdmin={isAdmin} />
          {error && <div className="error">{error}</div>}
          <button type="submit" disabled={submitting}>
            {submitting ? 'Unlocking…' : 'Get full report'}
          </button>
        </form>
      ) : (
        <p>Redirecting to your full report…</p>
      )}

      <div style={{ marginTop: 16 }}>
        <button type="button" className="secondary" onClick={onReset}>
          Scan another site
        </button>
      </div>
      </div>
    </div>
  );
}
