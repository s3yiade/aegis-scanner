'use client';

import { useEffect, useState } from 'react';
import { useCaptcha } from '@/hooks/useCaptcha';
import CaptchaField from '@/components/CaptchaField';
import { useIsAdmin } from '@/hooks/useIsAdmin';
import { useIdleTimeout } from '@/hooks/useIdleTimeout';
import { IDLE_TIMEOUT_MS } from '@/lib/idleConfig';

interface MyScan {
  id: string;
  hostname: string;
  target_url: string;
  score: number;
  grade: string;
  scanned_at: string;
  clone_candidate_count: number;
}

function gradeColor(grade: string) {
  return (
    { A: 'var(--pass)', B: 'var(--low)', C: 'var(--medium)', D: 'var(--high)', F: 'var(--critical)' }[grade] ??
    'var(--muted)'
  );
}

export default function MyDomains() {
  const { isAdmin, adminEmail } = useIsAdmin();
  const [email, setEmail] = useState('');
  const captcha = useCaptcha();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scans, setScans] = useState<MyScan[] | null>(null);

  useEffect(() => {
    if (isAdmin && adminEmail) setEmail((prev) => prev || adminEmail);
  }, [isAdmin, adminEmail]);

  // Clear the email field and any looked-up results after a few minutes
  // idle — this list ties an email to the domains scanned under it, which
  // is worth treating as sensitive on a shared/unattended screen.
  useIdleTimeout(IDLE_TIMEOUT_MS, () => {
    setEmail('');
    setScans(null);
  });

  async function handleLookup(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/my-scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Something went wrong.');
        captcha.reload();
        return;
      }
      setScans(data.scans ?? []);
    } catch {
      setError('Network error — please try again.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Your previous scans</h3>
      <p className="muted">
        Enter the email you used to unlock a report to see the domains you&apos;ve scanned with it. Each domain is
        listed separately — actions like the fix guide, a consult, or domain watch are purchased per domain, not
        per email.
      </p>

      <form onSubmit={handleLookup}>
        <label htmlFor="my-scans-email">Email</label>
        <input
          id="my-scans-email"
          type="email"
          required
          maxLength={320}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@business.com"
        />
        <CaptchaField captcha={captcha} isAdmin={isAdmin} />
        {error && <div className="error">{error}</div>}
        <button type="submit" disabled={loading}>
          {loading ? 'Looking up…' : 'Find my scans'}
        </button>
      </form>

      {scans !== null && (
        <div style={{ marginTop: 16 }}>
          {scans.length === 0 ? (
            <p className="muted">No scans found for that email.</p>
          ) : (
            scans.map((scan) => (
              <a key={scan.id} href={`/report/${scan.id}`} className="admin-scan-row">
                <div>
                  <strong>{scan.hostname}</strong>
                  <div className="muted" style={{ fontSize: '0.85rem' }}>
                    {new Date(scan.scanned_at).toLocaleString()}
                    {scan.clone_candidate_count > 0 ? ` · ${scan.clone_candidate_count} clone candidate(s)` : ''}
                  </div>
                </div>
                <div className="score-badge-small" style={{ borderColor: gradeColor(scan.grade), color: gradeColor(scan.grade) }}>
                  {scan.grade}
                </div>
              </a>
            ))
          )}
        </div>
      )}
    </div>
  );
}
