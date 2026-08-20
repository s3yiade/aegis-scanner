import { Resend } from 'resend';

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

/** Real-time notification to you when a new scan/lead comes in (Part 3, last idea). */
export async function notifyNewLead(input: {
  email: string;
  name?: string | null;
  hostname: string;
  score: number;
  grade: string;
  scanId: string;
}) {
  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  const reportUrl = `${appUrl}/report/${input.scanId}`;
  const text = `New lead: ${input.email}${input.name ? ` (${input.name})` : ''}\nScanned: ${input.hostname}\nScore: ${input.score} (${input.grade})\nReport: ${reportUrl}`;

  await Promise.allSettled([sendSlackDigest(text), sendEmailDigest('New Aegis lead', text)]);
}

/** Real-time notification when someone requests the gated clone-detection
 * deep dive (consult or paywall-intent) — this is a higher-intent lead than
 * a plain report unlock, worth flagging distinctly in the digest. */
export async function notifyConsultRequest(input: {
  email: string;
  name?: string | null;
  hostname: string;
  requestType: 'clone_report' | 'clone_report_paid_interest' | 'general';
  scanId: string;
}) {
  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  const reportUrl = input.scanId ? `${appUrl}/report/${input.scanId}` : null;
  const label =
    input.requestType === 'clone_report_paid_interest'
      ? 'PAID INTEREST'
      : input.requestType === 'general'
      ? 'general inquiry'
      : 'consult request';
  const text = `New ${label}: ${input.email}${input.name ? ` (${input.name})` : ''}\nSite: ${input.hostname}${reportUrl ? `\nReport: ${reportUrl}` : ''}`;

  await Promise.allSettled([sendSlackDigest(text), sendEmailDigest('New Aegis consult request', text)]);
}

/** Alerts a paying subscriber that a previously-dormant lookalike domain
 * has gone live and scores within their configured similarity range —
 * see api/cron/clone-watch. Includes an "escalate" link the recipient can
 * use to flag it for your direct follow-up (creates a high-priority
 * consult_requests row rather than requiring them to fill out a form). */
export async function sendCloneWatchAlert(input: {
  toEmail: string;
  hostname: string;
  cloneDomain: string;
  similarityPercent: number;
  escalateUrl: string;
  unsubscribeUrl: string;
}) {
  if (!resend || !process.env.DIGEST_FROM_EMAIL) return;
  const { error } = await resend.emails.send({
    from: process.env.DIGEST_FROM_EMAIL,
    to: input.toEmail,
    subject: `Possible clone site detected for ${input.hostname}`,
    text: [
      `A domain you're watching, ${input.cloneDomain}, just came online and scores ${input.similarityPercent}% similar to ${input.hostname}.`,
      `This is often how phishing/clone sites work: register a lookalike domain, then activate it once the copy is ready.`,
      '',
      `Escalate to your consultant now: ${input.escalateUrl}`,
      '',
      `Unsubscribe from this watch: ${input.unsubscribeUrl}`,
    ].join('\n'),
  });
  // Resend's SDK resolves with { error } rather than throwing on API-level
  // failures — logged (not thrown) since this runs from a cron job and one
  // failed alert shouldn't abort the rest of that run's clone checks.
  if (error) console.error(`Resend rejected clone-watch alert to ${input.toEmail}:`, error);
}

async function sendSlackDigest(text: string) {
  const webhook = process.env.SLACK_WEBHOOK_URL;
  if (!webhook) return;
  await fetch(webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
}

async function sendEmailDigest(subject: string, text: string) {
  if (!resend || !process.env.DIGEST_TO_EMAIL || !process.env.DIGEST_FROM_EMAIL) return;
  const { error } = await resend.emails.send({
    from: process.env.DIGEST_FROM_EMAIL,
    to: process.env.DIGEST_TO_EMAIL,
    subject,
    text,
  });
  // Called via Promise.allSettled from notifyNewLead/notifyConsultRequest —
  // logged rather than thrown so a rejected digest email never blocks or
  // fails the lead/consult request itself, but still visible in logs.
  if (error) console.error(`Resend rejected digest email "${subject}":`, error);
}

/** Weekly/daily monitoring alert when a watched site's score changes (Part 3, idea #3). */
export async function sendMonitorAlert(input: {
  toEmail: string;
  hostname: string;
  previousScore: number;
  newScore: number;
  grade: string;
  reportUrl: string;
  unsubscribeUrl: string;
}) {
  if (!resend || !process.env.DIGEST_FROM_EMAIL) return;
  const delta = input.newScore - input.previousScore;
  const direction = delta === 0 ? 'unchanged' : delta > 0 ? 'improved' : 'dropped';

  const { error } = await resend.emails.send({
    from: process.env.DIGEST_FROM_EMAIL,
    to: input.toEmail,
    subject: `${input.hostname} security score ${direction}: ${input.previousScore} → ${input.newScore}`,
    text: [
      `Your monitored site ${input.hostname} was re-scanned.`,
      `Previous score: ${input.previousScore}`,
      `New score: ${input.newScore} (${input.grade})`,
      '',
      `Full report: ${input.reportUrl}`,
      '',
      `Unsubscribe from monitoring: ${input.unsubscribeUrl}`,
    ].join('\n'),
  });
  // Called from the rescan cron — logged rather than thrown so a rejected
  // alert email never aborts the rest of that run's monitor rechecks.
  if (error) console.error(`Resend rejected monitor alert to ${input.toEmail}:`, error);
}
