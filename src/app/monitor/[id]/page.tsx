'use client';

import { useEffect, useState } from 'react';
import { useParams, useSearchParams } from 'next/navigation';
import TopNav from '@/components/TopNav';
import SiteFooter from '@/components/SiteFooter';
import BackBar from '@/components/BackBar';

interface DiffFinding {
  id: string;
  category: string;
  title: string;
  severity: string;
  detail: string;
}

interface DiffEntry {
  id: string;
  newScanId: string | null;
  scoreDelta: number;
  added: DiffFinding[];
  resolved: DiffFinding[];
  changed: { key: string; title: string; from: string; to: string }[];
  createdAt: string;
}

interface DiffHistoryResponse {
  monitor: {
    hostname: string;
    targetUrl: string;
    frequency: string;
    active: boolean;
    lastScore: number | null;
    proActivatedAt: string | null;
  };
  diffs: DiffEntry[];
}

function severityBg(s: string) {
  return (
    { critical: '#d92b2b', high: '#e07b00', medium: '#e0b400', low: '#4f7cff', info: '#8b93a7', pass: '#1ea34c' }[s] ?? '#8b93a7'
  );
}

export default function MonitorDiffPage() {
  const params = useParams<{ id: string }>();
  const searchParams = useSearchParams();
  const token = searchParams.get('token');

  const [data, setData] = useState<DiffHistoryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [portalLoading, setPortalLoading] = useState(false);
  const [portalError, setPortalError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setError('Missing access token — use the link from your diff alert email.');
      setLoading(false);
      return;
    }
    fetch(`/api/monitor/${params.id}/diffs?token=${encodeURIComponent(token)}`)
      .then(async (res) => {
        const json = await res.json();
        if (!res.ok) throw new Error(json.error || 'Could not load diff history.');
        setData(json);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [params.id, token]);

  async function handleManageBilling() {
    if (!token) return;
    setPortalLoading(true);
    setPortalError(null);
    try {
      const res = await fetch('/api/stripe/portal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ monitorId: params.id, token }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || 'Could not open billing portal.');
      window.location.href = json.portalUrl;
    } catch (err) {
      setPortalError(err instanceof Error ? err.message : 'Could not open billing portal.');
      setPortalLoading(false);
    }
  }

  return (
    <div className="container">
      <TopNav active="/saas" />
      <BackBar />

      <div className="hero">
        <h1>Continuous monitoring — diff history</h1>
        <p>Every re-scan compared against the one before it: what broke, what got fixed, what changed severity.</p>
      </div>

      {loading && <p className="muted">Loading…</p>}
      {error && <div className="card error">{error}</div>}

      {data && (
        <>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>{data.monitor.hostname}</h3>
            <p className="muted" style={{ marginBottom: 12 }}>
              {data.monitor.active ? 'Active' : 'Paused'} — re-scanning {data.monitor.frequency}
              {data.monitor.lastScore !== null && <> · current score: {data.monitor.lastScore}</>}
            </p>
            <button type="button" onClick={handleManageBilling} disabled={portalLoading}>
              {portalLoading ? 'Opening billing portal…' : 'Manage / cancel subscription'}
            </button>
            {portalError && <div className="error" style={{ marginTop: 8 }}>{portalError}</div>}
          </div>

          {data.diffs.length === 0 && (
            <p className="muted">
              No diffs yet — this shows up after the second re-scan since Pro monitoring was enabled (the first scan is the baseline,
              there&apos;s nothing to compare it to).
            </p>
          )}

          {data.diffs.map((diff) => (
            <div className="card" key={diff.id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8 }}>
                <strong>{new Date(diff.createdAt).toLocaleString()}</strong>
                {diff.scoreDelta !== 0 && (
                  <span className={diff.scoreDelta > 0 ? 'ok' : 'high'}>
                    {diff.scoreDelta > 0 ? '+' : ''}
                    {diff.scoreDelta} score
                  </span>
                )}
                {diff.newScanId && (
                  <a href={`/report/${diff.newScanId}`} className="muted" style={{ fontSize: '0.85rem' }}>
                    View full report →
                  </a>
                )}
              </div>

              {diff.added.length === 0 && diff.resolved.length === 0 && diff.changed.length === 0 && (
                <p className="muted" style={{ marginBottom: 0 }}>
                  No change from the previous scan.
                </p>
              )}

              {diff.added.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div className="muted" style={{ fontSize: '0.85rem', marginBottom: 4 }}>
                    New issues ({diff.added.length})
                  </div>
                  {diff.added.map((f) => (
                    <div className={`finding ${f.severity}`} key={`${f.category}:${f.id}`}>
                      <div className="title">
                        {f.title}
                        <span className="severity-tag" style={{ background: severityBg(f.severity), color: '#0b0f19' }}>
                          {f.severity}
                        </span>
                      </div>
                      <div className="detail">{f.detail}</div>
                    </div>
                  ))}
                </div>
              )}

              {diff.resolved.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div className="muted" style={{ fontSize: '0.85rem', marginBottom: 4 }}>
                    Resolved ({diff.resolved.length})
                  </div>
                  {diff.resolved.map((f) => (
                    <div className="finding pass" key={`${f.category}:${f.id}`}>
                      <div className="title">{f.title}</div>
                    </div>
                  ))}
                </div>
              )}

              {diff.changed.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div className="muted" style={{ fontSize: '0.85rem', marginBottom: 4 }}>
                    Severity changed ({diff.changed.length})
                  </div>
                  {diff.changed.map((c) => (
                    <div className="finding medium" key={c.key}>
                      <div className="title">
                        {c.title}
                        <span style={{ fontWeight: 400, fontSize: '0.85rem' }}>
                          {' '}
                          — {c.from} → {c.to}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </>
      )}

      <SiteFooter />
    </div>
  );
}
