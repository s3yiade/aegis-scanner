'use client';

import { use, useEffect, useState } from 'react';
import type { Finding } from '@/types/scan';
import { useCaptcha } from '@/hooks/useCaptcha';
import CaptchaField from '@/components/CaptchaField';
import { useIdleTimeout } from '@/hooks/useIdleTimeout';
import { useIsAdmin } from '@/hooks/useIsAdmin';
import { IDLE_TIMEOUT_MS } from '@/lib/idleConfig';
import { groupByCategory } from '@/lib/scanner/categories';
import { summarizeCompliance, FRAMEWORK_META, COMPLIANCE_DISCLAIMER, type ComplianceFramework } from '@/lib/scanner/compliance';
import BackBar from '@/components/BackBar';

interface FullReport {
  unlocked: boolean;
  hostname: string;
  score: number;
  grade: string;
  criticalCount?: number;
  targetUrl?: string;
  targetType?: string;
  findings?: Finding[];
  scannedAt?: string;
  niche?: string | null;
  nicheCopy?: { label: string; whyItMatters: string; exposureFraming: string };
  endpointType?: string | null;
  endpointCopy?: { label: string; whyItMatters: string; probePaths: string[] } | null;
  benchmark?: { avgScore: number; avgGrade: string; sampleSize: number } | null;
  cloneCandidateCount: number;
}

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [report, setReport] = useState<FullReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [monitorEmail, setMonitorEmail] = useState('');
  const [monitorStatus, setMonitorStatus] = useState<'idle' | 'saving' | 'done' | 'error'>('idle');
  const [monitorError, setMonitorError] = useState<string | null>(null);
  const captcha = useCaptcha();
  const [idled, setIdled] = useState(false);
  const [resumeEmail, setResumeEmail] = useState('');
  const [resumeError, setResumeError] = useState<string | null>(null);
  const [resuming, setResuming] = useState(false);
  const [showBookConsult, setShowBookConsult] = useState(false);
  const [badgeStyleState, setBadgeStyleState] = useState<'detailed' | 'compact'>('detailed');
  const { isAdmin, adminEmail } = useIsAdmin();

  useEffect(() => {
    fetch(`/api/report/${id}`)
      .then((r) => r.json())
      .then(setReport)
      .finally(() => setLoading(false));
  }, [id]);

  useEffect(() => {
    if (isAdmin && adminEmail) setMonitorEmail((prev) => prev || adminEmail);
  }, [isAdmin, adminEmail]);

  // After a few minutes of inactivity (see lib/idleConfig), clear what's currently displayed —
  // this never touches the underlying database record (still there,
  // unchanged); it's purely a privacy measure for a screen left open and
  // unattended. Re-entering the email that unlocked this report restores
  // the view. See api/report/[id]/resume for the (lightweight) check.
  useIdleTimeout(IDLE_TIMEOUT_MS, () => {
    setReport(null);
    setIdled(true);
  });

  async function handleResume(e: React.FormEvent) {
    e.preventDefault();
    setResuming(true);
    setResumeError(null);
    try {
      const res = await fetch(`/api/report/${id}/resume`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resumeEmail }),
      });
      const data = await res.json();
      if (!res.ok) {
        setResumeError(data.error || 'Could not verify that email.');
        return;
      }
      const reportRes = await fetch(`/api/report/${id}`);
      setReport(await reportRes.json());
      setIdled(false);
    } catch {
      setResumeError('Network error — please try again.');
    } finally {
      setResuming(false);
    }
  }

  async function handleMonitor(e: React.FormEvent) {
    e.preventDefault();
    setMonitorStatus('saving');
    setMonitorError(null);
    try {
      const res = await fetch('/api/monitor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId: id,
          email: monitorEmail,
          frequency: 'weekly',
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setMonitorError(data.error || 'Something went wrong.');
        captcha.reload();
        setMonitorStatus('error');
        return;
      }
      setMonitorStatus('done');
    } catch {
      setMonitorStatus('error');
    }
  }

  if (loading) {
    return (
      <div className="container">
        <p className="muted">Loading report…</p>
      </div>
    );
  }

  if (idled) {
    return (
      <div className="container">
        <BackBar />
        <div className="card locked-overlay">
          <h2>Session paused</h2>
          <p className="muted">
            This report was cleared from the screen after a few minutes of inactivity. Nothing was deleted — enter the
            email you used to unlock it to view it again.
          </p>
          <form onSubmit={handleResume} style={{ textAlign: 'left', marginTop: 16 }}>
            <label htmlFor="resume-email">Email</label>
            <input
              id="resume-email"
              type="email"
              required
              maxLength={320}
              value={resumeEmail}
              onChange={(e) => setResumeEmail(e.target.value)}
              placeholder="you@business.com"
            />
            {resumeError && <div className="error">{resumeError}</div>}
            <button type="submit" disabled={resuming}>
              {resuming ? 'Checking…' : 'View my report'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="container">
        <p>Report not found.</p>
      </div>
    );
  }

  if (!report.unlocked) {
    return (
      <div className="container">
        <BackBar />
        <div className="card locked-overlay">
          <h2>{report.hostname}</h2>
          <p className="muted">
            Score {report.score}/100 (Grade {report.grade}) — {report.criticalCount} critical issue(s) found.
          </p>
          {report.cloneCandidateCount > 0 && (
            <p className="muted">
              {report.cloneCandidateCount} registered domain{report.cloneCandidateCount > 1 ? 's' : ''} found with a
              name closely resembling yours — worth a manual look; unlock the full report for details.
            </p>
          )}
          <p>Submit your email from the scan page to unlock the full report.</p>
        </div>
      </div>
    );
  }

  const findings = report.findings ?? [];
  const failed = findings.filter((f) => !f.passed);
  const passed = findings.filter((f) => f.passed);
  const badgeStyle = badgeStyleState;
  const badgeUrl = `/api/badge/${id}${badgeStyle === 'compact' ? '?style=compact' : ''}`;
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const embedSnippet = `<a href="${origin}/report/${id}"><img src="${origin}${badgeUrl}" alt="Security scan badge" /></a>`;

  return (
    <div className="container">
      <BackBar />
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 8 }}>
          <div className="score-badge" style={{ borderColor: gradeColor(report.grade), color: gradeColor(report.grade) }}>
            {report.grade}
          </div>
          <div>
            <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>{report.hostname}</div>
            <div className="muted">
              Score {report.score}/100 · Scanned {report.scannedAt ? new Date(report.scannedAt).toLocaleString() : ''} ·{' '}
              {report.targetType === 'api' ? 'API target' : 'Web target'}
            </div>
          </div>
        </div>

        {report.nicheCopy && (
          <p className="muted" style={{ marginTop: 12 }}>
            <strong>Why this matters for {report.nicheCopy.label.toLowerCase()}:</strong> {report.nicheCopy.whyItMatters}
          </p>
        )}

        {report.endpointCopy && (
          <p className="muted" style={{ marginTop: 12 }}>
            <strong>Why this matters for a {report.endpointCopy.label.toLowerCase()}:</strong> {report.endpointCopy.whyItMatters}
          </p>
        )}

        {report.benchmark && (
          <p className="muted">
            Businesses in this category average a {report.benchmark.avgGrade} ({Math.round(report.benchmark.avgScore)}
            /100) across {report.benchmark.sampleSize} scans.
          </p>
        )}

        <div className="actions" style={{ marginTop: 16 }}>
          <a href={`/api/report/${id}/pdf`}>Download PDF report</a>
          <a href={badgeUrl} target="_blank" rel="noreferrer">
            View badge
          </a>
        </div>
      </div>

      {failed.length > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Issues found ({failed.length})</h3>
          {groupByCategory(failed).map((group) => (
            <div key={group.category} className="finding-category-group">
              <h4 className="finding-category-heading">{group.label}</h4>
              {group.findings
                .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
                .map((f) => (
                  <FindingRow key={f.id} finding={f} />
                ))}
            </div>
          ))}
        </div>
      )}

      {passed.length > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Passing checks ({passed.length})</h3>
          {groupByCategory(passed).map((group) => (
            <div key={group.category} className="finding-category-group">
              <h4 className="finding-category-heading">{group.label}</h4>
              {group.findings.map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </div>
          ))}
        </div>
      )}

      <ComplianceSection findings={findings} />

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Get alerted if this changes</h3>
        <p className="muted">Free weekly re-scan with an email alert if the score moves.</p>
        {monitorStatus === 'done' ? (
          <p>You&apos;re subscribed to weekly monitoring for {report.hostname}.</p>
        ) : (
          <form onSubmit={handleMonitor}>
            <input
              type="email"
              required
              maxLength={320}
              placeholder="you@business.com"
              value={monitorEmail}
              onChange={(e) => setMonitorEmail(e.target.value)}
            />
            <CaptchaField captcha={captcha} isAdmin={isAdmin} />
            <button type="submit" disabled={monitorStatus === 'saving'}>
              {monitorStatus === 'saving' ? 'Saving…' : 'Enable weekly monitoring'}
            </button>
            {monitorStatus === 'error' && <div className="error">{monitorError || 'Could not set up monitoring — try again.'}</div>}
          </form>
        )}
      </div>

      {report.targetType === 'api' && <SaasMonitorProCard scanId={id} isAdmin={isAdmin} adminEmail={adminEmail} />}

      <CloneProtectionCard scanId={id} cloneCandidateCount={report.cloneCandidateCount} isAdmin={isAdmin} adminEmail={adminEmail} />

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Show your score</h3>
        <p className="muted">
          Embed this badge on your site — it shows your grade, score, and scan date, and visibly flags itself as due for a
          re-scan after {60} days rather than displaying a stale result indefinitely.
        </p>
        <div className="badge-style-toggle" role="group" aria-label="Badge style">
          <button type="button" className={badgeStyleState === 'detailed' ? 'active' : ''} onClick={() => setBadgeStyleState('detailed')}>
            Detailed
          </button>
          <button type="button" className={badgeStyleState === 'compact' ? 'active' : ''} onClick={() => setBadgeStyleState('compact')}>
            Compact
          </button>
        </div>
        <img src={badgeUrl} alt="Security scan badge" />
        <textarea
          readOnly
          value={embedSnippet}
          style={{ width: '100%', marginTop: 10, background: '#0e1424', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 8, padding: 10, fontSize: '0.8rem' }}
          rows={2}
          onFocus={(e) => e.currentTarget.select()}
        />
      </div>

      <FixYourselfCard scanId={id} isAdmin={isAdmin} adminEmail={adminEmail} />

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Want this handled for you?</h3>
        <p className="muted">Talk to us directly about fixing what this report found.</p>
        <button type="button" onClick={() => setShowBookConsult(true)}>
          Book a consult
        </button>
      </div>

      {showBookConsult && (
        <BookConsultModal scanId={id} onClose={() => setShowBookConsult(false)} isAdmin={isAdmin} adminEmail={adminEmail} />
      )}
    </div>
  );
}

function BookConsultModal({
  scanId,
  onClose,
  isAdmin,
  adminEmail,
}: {
  scanId: string;
  onClose: () => void;
  isAdmin: boolean;
  adminEmail: string | null;
}) {
  const captcha = useCaptcha();
  const [name, setName] = useState('');
  const [email, setEmail] = useState(adminEmail ?? '');
  const [message, setMessage] = useState('');
  const [status, setStatus] = useState<'idle' | 'submitting' | 'done' | 'error'>('idle');
  const [error, setError] = useState<string | null>(null);


  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus('submitting');
    setError(null);
    try {
      const res = await fetch('/api/consult', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId,
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
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal-content">
        <button type="button" className="modal-back" onClick={onClose} aria-label="Back">
          &larr; Back
        </button>
        <h3 style={{ marginTop: 8 }}>Book a consult</h3>
        <p className="muted">Tell us a bit about what you need — we&apos;ll follow up to schedule a time.</p>

        {status === 'done' ? (
          <p>Thanks — we&apos;ll be in touch shortly.</p>
        ) : (
          <form onSubmit={handleSubmit}>
            <label htmlFor="book-name">Name</label>
            <input id="book-name" type="text" maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
            <label htmlFor="book-email">Email</label>
            <input
              id="book-email"
              type="email"
              required
              maxLength={320}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@business.com"
            />
            <label htmlFor="book-message">What would you like to cover?</label>
            <input id="book-message" type="text" maxLength={1000} value={message} onChange={(e) => setMessage(e.target.value)} />

            <CaptchaField captcha={captcha} isAdmin={isAdmin} />

            {error && <div className="error">{error}</div>}

            <button type="submit" disabled={status === 'submitting'}>
              {status === 'submitting' ? 'Sending…' : 'Request a consult'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

function SaasMonitorProCard({ scanId, isAdmin, adminEmail }: { scanId: string; isAdmin: boolean; adminEmail: string | null }) {
  const captcha = useCaptcha();
  const [email, setEmail] = useState(adminEmail ?? '');
  const [frequency, setFrequency] = useState<'daily' | 'weekly'>('daily');
  const [status, setStatus] = useState<'idle' | 'submitting' | 'error' | 'active'>('idle');
  const [error, setError] = useState<string | null>(null);

  async function handleUpgrade(e: React.FormEvent) {
    e.preventDefault();
    setStatus('submitting');
    setError(null);
    try {
      const res = await fetch('/api/stripe/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId,
          product: 'saas_monitor_pro',
          email,
          frequency,
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Could not start checkout.');
        captcha.reload();
        setStatus('error');
        return;
      }
      if (data.adminGranted) {
        setStatus('active');
        return;
      }
      if (data.checkoutUrl) {
        window.location.href = data.checkoutUrl;
        return;
      }
      setStatus('idle');
    } catch {
      setError('Network error — please try again.');
      setStatus('error');
    }
  }

  if (status === 'active') {
    return (
      <div className="card">
        <h3 style={{ marginTop: 0 }}>Continuous monitoring — Pro</h3>
        <p>Pro monitoring is active. You&apos;ll get a diff email whenever something changes, plus the ability to review the full history.</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Continuous monitoring — Pro</h3>
      <p className="muted">
        Everything the free monitor does, plus a structured diff report on every re-scan — exactly which checks started failing,
        which got fixed, and which changed severity, not just the overall score. Built for SaaS/API targets, where a single new
        endpoint or a changed CORS policy is worth knowing about the day it happens, not whenever someone next runs a manual scan.
      </p>
      <form onSubmit={handleUpgrade}>
        <input
          type="email"
          required
          maxLength={320}
          placeholder="you@business.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <label htmlFor="pro-frequency">Re-scan frequency</label>
        <select id="pro-frequency" value={frequency} onChange={(e) => setFrequency(e.target.value as 'daily' | 'weekly')}>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
        </select>
        <CaptchaField captcha={captcha} isAdmin={isAdmin} />
        <button type="submit" disabled={status === 'submitting'}>
          {status === 'submitting' ? 'Starting checkout…' : 'Upgrade to continuous monitoring'}
        </button>
        {status === 'error' && <div className="error">{error || 'Could not start checkout — try again.'}</div>}
      </form>
    </div>
  );
}

function FixYourselfCard({ scanId, isAdmin, adminEmail }: { scanId: string; isAdmin: boolean; adminEmail: string | null }) {
  const captcha = useCaptcha();
  const [email, setEmail] = useState(adminEmail ?? '');
  const [status, setStatus] = useState<'idle' | 'submitting' | 'error'>('idle');
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  // Fix procedures are ONLY ever fetched from /api/report/[id]/fix-guide
  // after a successful unlock — never present in the main report payload,
  // by design (see that route's comments).
  const [procedures, setProcedures] = useState<
    { findingId: string; findingTitle: string; severity: string; procedure: { title: string; steps: string[]; estimatedTime: string } }[] | null
  >(null);

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    setStatus('submitting');
    setError(null);
    try {
      const res = await fetch('/api/stripe/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId,
          product: 'fix_guide_unlock',
          email,
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Could not start checkout.');
        captcha.reload();
        setStatus('error');
        return;
      }
      if (data.adminGranted) {
        // Admin session — access was granted directly, no Stripe redirect.
        // Fetch the guide immediately instead of round-tripping through checkout.
        const guideRes = await fetch(`/api/report/${scanId}/fix-guide`);
        const guideData = await guideRes.json();
        setProcedures(guideData.procedures ?? []);
        setStatus('idle');
        return;
      }
      if (data.checkoutUrl) {
        window.location.href = data.checkoutUrl;
        return;
      }
      setStatus('idle');
    } catch {
      setError('Network error — please try again.');
      setStatus('error');
    }
  }


  if (procedures) {
    return (
      <div className="card">
        <h3 style={{ marginTop: 0 }}>Fix-it-yourself guide</h3>
        {procedures.length === 0 ? (
          <p className="muted">No failed findings to fix — nice.</p>
        ) : (
          procedures.map((p) => (
            <div key={p.findingId} className={`finding ${p.severity}`}>
              <div className="title">{p.findingTitle}</div>
              <div className="detail" style={{ marginTop: 6 }}>
                <strong>{p.procedure.title}</strong> · {p.procedure.estimatedTime}
              </div>
              <ol style={{ margin: '8px 0 0', paddingLeft: 20, color: 'var(--muted)', fontSize: '0.92rem' }}>
                {p.procedure.steps.map((step, i) => (
                  <li key={i} style={{ marginBottom: 4 }}>
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          ))
        )}
      </div>
    );
  }

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Fix it yourself</h3>
      <p className="muted">
        Every finding above comes with a one-line recommendation for free. Unlock the full step-by-step procedure
        for each one — exact commands, config snippets, and what to verify afterward. Never shown as part of the
        free report; this is a separate, gated unlock.
      </p>

      {!showForm ? (
        <button type="button" onClick={() => setShowForm(true)}>
          Unlock full fix procedures
        </button>
      ) : (
        <form onSubmit={handleUnlock}>
          <label htmlFor="fixguide-email">Email</label>
          <input
            id="fixguide-email"
            type="email"
            required
            maxLength={320}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@business.com"
          />
          <CaptchaField captcha={captcha} isAdmin={isAdmin} />
          {error && <div className="error">{error}</div>}
          <button type="submit" disabled={status === 'submitting'}>
            {status === 'submitting' ? 'Starting checkout…' : 'Continue to payment'}
          </button>
        </form>
      )}
    </div>
  );
}

function CloneProtectionCard({
  scanId,
  cloneCandidateCount,
  isAdmin,
  adminEmail,
}: {
  scanId: string;
  cloneCandidateCount: number;
  isAdmin: boolean;
  adminEmail: string | null;
}) {
  const captcha = useCaptcha();
  const [name, setName] = useState('');
  const [email, setEmail] = useState(adminEmail ?? '');
  const [message, setMessage] = useState('');
  const [status, setStatus] = useState<'idle' | 'submitting' | 'done' | 'error'>('idle');
  const [error, setError] = useState<string | null>(null);
  const [completedType, setCompletedType] = useState<'clone_report' | null>(null);
  const [submittingAction, setSubmittingAction] = useState<'consult' | 'unlock' | null>(null);
  const [showWatchModal, setShowWatchModal] = useState(false);


  async function submitConsult() {
    setSubmittingAction('consult');
    setStatus('submitting');
    setError(null);
    try {
      const res = await fetch('/api/consult', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId,
          email,
          name: name || undefined,
          message: message || undefined,
          requestType: 'clone_report',
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
      setCompletedType('clone_report');
      setStatus('done');
    } catch {
      setStatus('error');
    } finally {
      setSubmittingAction(null);
    }
  }

  async function submitUnlockPayment() {
    setSubmittingAction('unlock');
    setStatus('submitting');
    setError(null);
    try {
      const res = await fetch('/api/stripe/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId,
          product: 'clone_report_unlock',
          email,
          name: name || undefined,
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.checkoutUrl) {
        setError(data.error || 'Could not start checkout.');
        captcha.reload();
        setStatus('error');
        return;
      }
      window.location.href = data.checkoutUrl; // hand off to Stripe Checkout
    } catch {
      setError('Network error — please try again.');
      setStatus('error');
    } finally {
      setSubmittingAction(null);
    }
  }

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Domain clone & phishing exposure</h3>
      <p className="muted">
        {cloneCandidateCount > 0
          ? `We found ${cloneCandidateCount} registered domain${cloneCandidateCount > 1 ? 's' : ''} whose name closely resembles yours. That's a common setup for phishing or brand-impersonation sites — it's also common for a name-match like this to be unrelated (a different company, a domain investor, pure coincidence), so treat this as a worth-checking list, not a confirmed-threat count.`
          : 'We check for lookalike domain registrations and cloned/mirrored copies of your site — a common phishing setup.'}
        {' '}The full list, plus a deeper similarity analysis, is available as part of a quick consult or an instant unlock.
      </p>
      <p className="muted">
        <strong>Why some of these might not be live sites yet:</strong> it's common for whoever registered a
        lookalike domain to sit on it — no website, nothing pointed at it — until the copy of your site is ready to
        go. A domain can be registered and completely dormant for weeks before it suddenly becomes a working phishing
        page. That's exactly what the paid &quot;notify me&quot; option below watches for.
      </p>

      {status === 'done' ? (
        <p>
          {completedType === 'clone_report' ? "Thanks — we'll be in touch shortly with the full findings." : null}
        </p>
      ) : (
        <div>
          <label htmlFor="clone-name">Name</label>
          <input id="clone-name" type="text" maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          <label htmlFor="clone-email">Email</label>
          <input
            id="clone-email"
            type="email"
            required
            maxLength={320}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@business.com"
          />
          <label htmlFor="clone-message">Anything specific you're worried about? (optional)</label>
          <input id="clone-message" type="text" maxLength={1000} value={message} onChange={(e) => setMessage(e.target.value)} />

          <CaptchaField captcha={captcha} isAdmin={isAdmin} />

          {error && <div className="error">{error}</div>}

          <div className="actions">
            <button type="button" onClick={submitConsult} disabled={status === 'submitting' || !email}>
              {submittingAction === 'consult' ? 'Sending…' : 'Request consultation'}
            </button>
            <button type="button" className="secondary" onClick={submitUnlockPayment} disabled={status === 'submitting' || !email}>
              {submittingAction === 'unlock' ? 'Starting checkout…' : 'Unlock instantly (paid)'}
            </button>
          </div>
          <div className="actions" style={{ marginTop: 10 }}>
            <button type="button" className="secondary" onClick={() => setShowWatchModal(true)}>
              Notify me if a dormant domain goes live
            </button>
          </div>
        </div>
      )}

      {showWatchModal && (
        <CloneWatchModal scanId={scanId} email={email} onClose={() => setShowWatchModal(false)} isAdmin={isAdmin} />
      )}
    </div>
  );
}

function CloneWatchModal({
  scanId,
  email: initialEmail,
  onClose,
  isAdmin,
}: {
  scanId: string;
  email: string;
  onClose: () => void;
  isAdmin: boolean;
}) {
  const captcha = useCaptcha();
  const [email, setEmail] = useState(initialEmail);
  const [similarityMin, setSimilarityMin] = useState(70);
  const [similarityMax, setSimilarityMax] = useState(90);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);


  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/stripe/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId,
          product: 'domain_watch_subscription',
          email,
          similarityMin,
          similarityMax,
          captcha: isAdmin ? {} : captcha.payload,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.checkoutUrl) {
        setError(data.error || 'Could not start checkout.');
        captcha.reload();
        setSubmitting(false);
        return;
      }
      window.location.href = data.checkoutUrl;
    } catch {
      setError('Network error — please try again.');
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal-content">
        <button type="button" className="modal-back" onClick={onClose} aria-label="Back">
          &larr; Back
        </button>
        <h3 style={{ marginTop: 8 }}>Get notified when a clone goes live</h3>
        <p className="muted">
          We'll keep checking the dormant lookalike domains found for this site. If one comes online and scores
          within your chosen similarity range against your real site, we'll email you immediately with an option to
          escalate straight to a consultant.
        </p>
        <form onSubmit={handleSubmit}>
          <label htmlFor="watch-email">Email</label>
          <input
            id="watch-email"
            type="email"
            required
            maxLength={320}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@business.com"
          />
          <label htmlFor="watch-min">Alert range (similarity %)</label>
          <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
            <input
              id="watch-min"
              type="number"
              min={0}
              max={100}
              value={similarityMin}
              onChange={(e) => setSimilarityMin(Number(e.target.value))}
              style={{ marginBottom: 0 }}
            />
            <span className="muted" style={{ alignSelf: 'center' }}>to</span>
            <input
              type="number"
              min={0}
              max={100}
              value={similarityMax}
              onChange={(e) => setSimilarityMax(Number(e.target.value))}
              style={{ marginBottom: 0 }}
            />
          </div>

          <CaptchaField captcha={captcha} isAdmin={isAdmin} />

          {error && <div className="error">{error}</div>}

          <button type="submit" disabled={submitting}>
            {submitting ? 'Starting checkout…' : 'Continue to payment'}
          </button>
        </form>
      </div>
    </div>
  );
}

function ComplianceSection({ findings }: { findings: Finding[] }) {
  const [expanded, setExpanded] = useState(false);
  const summary = summarizeCompliance(findings);
  const frameworks = Object.keys(summary) as ComplianceFramework[];
  const totalMapped = frameworks.reduce((sum, fw) => sum + summary[fw].length, 0);

  if (totalMapped === 0) return null;

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Compliance framework mapping</h3>
      <p className="muted" style={{ fontSize: '0.85rem' }}>{COMPLIANCE_DISCLAIMER}</p>

      <div className="compliance-framework-grid">
        {frameworks.map((fw) => {
          const controls = summary[fw];
          if (controls.length === 0) return null;
          const gaps = controls.filter((c) => c.status === 'gap');
          return (
            <div className="compliance-framework-card" key={fw}>
              <div className="compliance-framework-title">{FRAMEWORK_META[fw].shortLabel}</div>
              <div className={gaps.length > 0 ? 'compliance-gap-count gap' : 'compliance-gap-count clear'}>
                {gaps.length > 0 ? `${gaps.length} control${gaps.length === 1 ? '' : 's'} to review` : 'No gaps flagged'}
              </div>
              <div className="muted" style={{ fontSize: '0.78rem' }}>{controls.length} control(s) touched by this scan</div>
            </div>
          );
        })}
      </div>

      <button type="button" className="modal-back" style={{ marginTop: 8 }} onClick={() => setExpanded((v) => !v)}>
        {expanded ? 'Hide control detail ▲' : 'Show control detail ▼'}
      </button>

      {expanded &&
        frameworks.map((fw) => {
          const controls = summary[fw];
          if (controls.length === 0) return null;
          return (
            <div key={fw} className="finding-category-group">
              <h4 className="finding-category-heading">{FRAMEWORK_META[fw].label}</h4>
              {controls.map((c) => (
                <div className={`finding ${c.status === 'gap' ? 'medium' : 'pass'}`} key={`${fw}:${c.controlId}`}>
                  <div className="title">
                    {c.controlId} — {c.controlTitle}
                    <span
                      className="severity-tag"
                      style={{ background: c.status === 'gap' ? '#e0b400' : '#1ea34c', color: '#0b0f19' }}
                    >
                      {c.status === 'gap' ? 'review' : 'clear'}
                    </span>
                  </div>
                  {c.relatedFindingTitles.length > 0 && (
                    <div className="detail">Related: {c.relatedFindingTitles.join(', ')}</div>
                  )}
                </div>
              ))}
            </div>
          );
        })}
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <div className={`finding ${finding.severity}`}>
      <div className="title">
        {finding.title}
        <span
          className="severity-tag"
          style={{ background: severityBg(finding.severity), color: '#0b0f19' }}
        >
          {finding.severity}
        </span>
      </div>
      <div className="detail">{finding.detail}</div>
      {!finding.passed && <div className="rec">Fix: {finding.recommendation}</div>}
    </div>
  );
}

function severityRank(s: string) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1, pass: 0 }[s] ?? 0;
}

function severityBg(s: string) {
  return (
    { critical: '#d92b2b', high: '#e07b00', medium: '#e0b400', low: '#4f7cff', info: '#8b93a7', pass: '#1ea34c' }[
      s
    ] ?? '#8b93a7'
  );
}

function gradeColor(grade: string) {
  return (
    { A: 'var(--pass)', B: 'var(--low)', C: 'var(--medium)', D: 'var(--high)', F: 'var(--critical)' }[grade] ??
    'var(--muted)'
  );
}
