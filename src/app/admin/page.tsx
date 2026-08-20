'use client';

import { useEffect, useState } from 'react';
import BackBar from '@/components/BackBar';

interface AdminScan {
  id: string;
  hostname: string;
  target_url: string;
  score: number;
  grade: string;
  scanned_at: string;
  clone_candidate_count: number;
}

interface ContentSimilarityMatch {
  url: string;
  title: string;
  snippet: string;
}

interface DeepScanFinding {
  id: string;
  category: string;
  title: string;
  severity: string;
  detail: string;
  recommendation: string;
  passed: boolean;
}

interface SimilarityComparison {
  candidateUrl: string;
  domSimilarity: number | null;
  faviconSimilarity: number | null;
  visualSimilarity: number | null;
  reverseImageMatchType: string | null;
  combinedScore: number;
  corroborated: boolean;
}

interface SimilarityResults {
  comparisons: SimilarityComparison[];
  additionalCandidatesFromReverseImage: string[];
}

interface CloneCandidate {
  domain: string;
  registrationStatus?: string;
}

interface ConsultRequestScan {
  hostname: string;
  target_url: string;
  score: number;
  grade: string;
  clone_candidates: CloneCandidate[] | null;
}

interface ConsultRequest {
  id: string;
  scan_id: string | null;
  email: string;
  name: string | null;
  request_type: string;
  message: string | null;
  created_at: string;
  contacted: boolean;
  paid: boolean;
  content_similarity_status: string;
  content_similarity_matches: ContentSimilarityMatch[] | null;
  deep_scan_status: string;
  deep_scan_findings: DeepScanFinding[] | null;
  similarity_status: string;
  similarity_results: SimilarityResults | null;
  scans: ConsultRequestScan | null;
}

export default function AdminPage() {
  const [checking, setChecking] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [codeRequested, setCodeRequested] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [scans, setScans] = useState<AdminScan[]>([]);
  const [scope, setScope] = useState<'mine' | 'all'>('mine');
  const [loadingScans, setLoadingScans] = useState(false);
  const [view, setView] = useState<'scans' | 'review'>('scans');
  const [requests, setRequests] = useState<ConsultRequest[]>([]);
  const [loadingRequests, setLoadingRequests] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  async function loadRequests() {
    setLoadingRequests(true);
    try {
      const res = await fetch('/api/admin/consult-requests');
      if (res.status === 401) {
        setAuthenticated(false);
        return;
      }
      const data = await res.json();
      setRequests(data.requests ?? []);
    } finally {
      setLoadingRequests(false);
    }
  }

  async function toggleContacted(req: ConsultRequest) {
    const next = !req.contacted;
    setRequests((prev) => prev.map((r) => (r.id === req.id ? { ...r, contacted: next } : r)));
    await fetch(`/api/admin/consult-requests/${req.id}/contacted`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contacted: next }),
    });
  }

  function handleViewChange(next: 'scans' | 'review') {
    setView(next);
    if (next === 'review' && requests.length === 0) loadRequests();
  }

  async function loadScans(nextScope: 'mine' | 'all') {
    setLoadingScans(true);
    try {
      const res = await fetch(`/api/admin/scans?scope=${nextScope}`);
      if (res.status === 401) {
        setAuthenticated(false);
        return;
      }
      const data = await res.json();
      setScans(data.scans ?? []);
      setAuthenticated(true);
    } finally {
      setLoadingScans(false);
    }
  }

  useEffect(() => {
    loadScans(scope).finally(() => setChecking(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleRequestCode() {
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/admin/request-code', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Could not send code.');
        return;
      }
      setCodeRequested(true);
    } catch {
      setError('Network error — please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleVerifyCode(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/admin/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Invalid code.');
        return;
      }
      await loadScans(scope);
    } catch {
      setError('Network error — please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleLogout() {
    await fetch('/api/admin/logout', { method: 'POST' });
    setAuthenticated(false);
    setCodeRequested(false);
    setCode('');
  }

  function handleScopeChange(next: 'mine' | 'all') {
    setScope(next);
    loadScans(next);
  }

  if (checking) {
    return (
      <div className="container">
        <p className="muted">Loading…</p>
      </div>
    );
  }

  if (!authenticated) {
    return (
      <div className="container">
        <BackBar />
        <div className="hero">
          <h1>Admin login</h1>
          <p>A one-time code will be emailed to the configured admin address.</p>
        </div>

        <div className="card">
          {!codeRequested ? (
            <button type="button" onClick={handleRequestCode} disabled={submitting}>
              {submitting ? 'Sending…' : 'Send login code'}
            </button>
          ) : (
            <form onSubmit={handleVerifyCode}>
              <label htmlFor="admin-code">24-digit code from your email</label>
              <input
                id="admin-code"
                type="text"
                inputMode="numeric"
                pattern="\d{24}"
                maxLength={24}
                required
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000000000000000000000"
              />
              {error && <div className="error">{error}</div>}
              <button type="submit" disabled={submitting || code.length !== 24}>
                {submitting ? 'Verifying…' : 'Verify & log in'}
              </button>
              <button type="button" className="secondary" onClick={handleRequestCode} disabled={submitting} style={{ marginTop: 10 }}>
                Resend code
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <BackBar />
      <div className="hero">
        <h1>Admin</h1>
        <p>Past scan reports and the review queue for consult requests.</p>
      </div>

      <div className="actions" style={{ marginBottom: 16 }}>
        <button type="button" className={view === 'scans' ? '' : 'secondary'} onClick={() => handleViewChange('scans')}>
          Scans
        </button>
        <button type="button" className={view === 'review' ? '' : 'secondary'} onClick={() => handleViewChange('review')}>
          Review queue{requests.filter((r) => !r.contacted).length > 0 && view !== 'review' ? ` (${requests.filter((r) => !r.contacted).length})` : ''}
        </button>
        <button type="button" className="secondary" onClick={handleLogout}>
          Log out
        </button>
      </div>

      {view === 'scans' && (
      <div className="card">
        <div className="actions" style={{ marginBottom: 16 }}>
          <button type="button" className={scope === 'mine' ? '' : 'secondary'} onClick={() => handleScopeChange('mine')}>
            My scans
          </button>
          <button type="button" className={scope === 'all' ? '' : 'secondary'} onClick={() => handleScopeChange('all')}>
            All scans
          </button>
        </div>

        {loadingScans ? (
          <p className="muted">Loading…</p>
        ) : scans.length === 0 ? (
          <p className="muted">No scans found for this view.</p>
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
              <div className="score-badge-small">{scan.grade}</div>
            </a>
          ))
        )}
      </div>
      )}

      {view === 'review' && (
        <div className="card">
          <p className="muted" style={{ marginTop: 0 }}>
            Every consult request, with the results of the async analysis pipelines (content-similarity title
            search, JS-rendered deep scan, DOM/favicon/screenshot/reverse-image comparisons) that run after
            someone submits one. This is the manual-verification step the clone-detection signals depend on —
            none of this should be treated as a confirmed finding without a look here first.
          </p>
          {loadingRequests ? (
            <p className="muted">Loading…</p>
          ) : requests.length === 0 ? (
            <p className="muted">No consult requests yet.</p>
          ) : (
            requests.map((r) => (
              <ReviewRow
                key={r.id}
                request={r}
                expanded={expandedId === r.id}
                onToggleExpand={() => setExpandedId(expandedId === r.id ? null : r.id)}
                onToggleContacted={() => toggleContacted(r)}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function statusBadge(status: string) {
  const color = status === 'complete' ? 'var(--pass)' : status === 'failed' ? 'var(--critical)' : status === 'pending' ? 'var(--medium)' : 'var(--muted)';
  return (
    <span style={{ color, fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.03em' }}>
      {status.replace(/_/g, ' ')}
    </span>
  );
}

function ReviewRow({
  request: r,
  expanded,
  onToggleExpand,
  onToggleContacted,
}: {
  request: ConsultRequest;
  expanded: boolean;
  onToggleExpand: () => void;
  onToggleContacted: () => void;
}) {
  return (
    <div className="admin-review-row" style={{ borderBottom: '1px solid var(--glass-border)', padding: '12px 0' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, cursor: 'pointer' }} onClick={onToggleExpand}>
        <div>
          <strong>{r.scans?.hostname ?? r.scan_id ?? 'Unknown target'}</strong>{' '}
          <span className="muted" style={{ fontSize: '0.85rem' }}>
            {r.email} · {r.request_type.replace(/_/g, ' ')} · {new Date(r.created_at).toLocaleString()}
          </span>
          <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
            <span className="muted" style={{ fontSize: '0.75rem' }}>Content search: {statusBadge(r.content_similarity_status)}</span>
            <span className="muted" style={{ fontSize: '0.75rem' }}>Deep scan: {statusBadge(r.deep_scan_status)}</span>
            <span className="muted" style={{ fontSize: '0.75rem' }}>Similarity: {statusBadge(r.similarity_status)}</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {r.paid && <span style={{ fontSize: '0.75rem', color: 'var(--pass)', fontWeight: 600 }}>PAID</span>}
          <button
            type="button"
            className={r.contacted ? 'secondary' : ''}
            onClick={(e) => {
              e.stopPropagation();
              onToggleContacted();
            }}
          >
            {r.contacted ? 'Contacted ✓' : 'Mark contacted'}
          </button>
        </div>
      </div>

      {expanded && (
        <div style={{ marginTop: 12, paddingLeft: 4 }}>
          {r.message && (
            <p className="muted" style={{ fontSize: '0.9rem' }}>
              <em>&ldquo;{r.message}&rdquo;</em>
            </p>
          )}

          {r.scans?.clone_candidates && r.scans.clone_candidates.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <h4 className="finding-category-heading">Clone candidates ({r.scans.clone_candidates.length})</h4>
              {r.scans.clone_candidates.map((c) => (
                <div key={c.domain} style={{ fontSize: '0.85rem' }}>
                  {c.domain} {c.registrationStatus === 'registered_dormant' ? <span className="muted">(dormant)</span> : null}
                </div>
              ))}
            </div>
          )}

          {r.similarity_results && r.similarity_results.comparisons.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <h4 className="finding-category-heading">Similarity comparisons</h4>
              {r.similarity_results.comparisons
                .sort((a, b) => b.combinedScore - a.combinedScore)
                .map((c) => (
                  <div key={c.candidateUrl} style={{ fontSize: '0.85rem', marginBottom: 6 }}>
                    <strong>{c.candidateUrl}</strong> — combined {Math.round(c.combinedScore * 100)}%
                    {c.corroborated ? <span style={{ color: 'var(--high)' }}> · corroborated (2+ strong signals)</span> : null}
                    <div className="muted" style={{ fontSize: '0.78rem' }}>
                      DOM: {fmtPct(c.domSimilarity)} · Favicon: {fmtPct(c.faviconSimilarity)} · Visual: {fmtPct(c.visualSimilarity)} · Reverse image: {c.reverseImageMatchType ?? 'none'}
                    </div>
                  </div>
                ))}
              {r.similarity_results.additionalCandidatesFromReverseImage.length > 0 && (
                <p className="muted" style={{ fontSize: '0.8rem' }}>
                  Also found via reverse image search (not in the original candidate list):{' '}
                  {r.similarity_results.additionalCandidatesFromReverseImage.join(', ')}
                </p>
              )}
            </div>
          )}

          {r.content_similarity_matches && r.content_similarity_matches.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <h4 className="finding-category-heading">Content/title matches</h4>
              {r.content_similarity_matches.map((m) => (
                <div key={m.url} style={{ fontSize: '0.85rem', marginBottom: 4 }}>
                  <a href={m.url} target="_blank" rel="noopener noreferrer">{m.title || m.url}</a>
                  <div className="muted" style={{ fontSize: '0.78rem' }}>{m.snippet}</div>
                </div>
              ))}
            </div>
          )}

          {r.deep_scan_findings && r.deep_scan_findings.length > 0 && (
            <div>
              <h4 className="finding-category-heading">Deep scan findings ({r.deep_scan_findings.filter((f) => !f.passed).length} issue(s))</h4>
              {r.deep_scan_findings
                .filter((f) => !f.passed)
                .map((f) => (
                  <div key={f.id} style={{ fontSize: '0.85rem', marginBottom: 4 }}>
                    <span style={{ fontWeight: 600 }}>[{f.severity.toUpperCase()}]</span> {f.title} — {f.detail}
                  </div>
                ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function fmtPct(v: number | null): string {
  return v === null ? 'n/a' : `${Math.round(v * 100)}%`;
}
