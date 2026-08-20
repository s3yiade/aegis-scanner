import tls from 'node:tls';
import type { Finding } from '@/types/scan';
import type { SafeTarget } from '@/lib/ssrfGuard';

const TIMEOUT_MS = 8000;
const WEAK_PROTOCOL_TEST_TIMEOUT_MS = 6000;

interface HandshakeResult {
  connected: boolean;
  protocol: string | null;
  cert: tls.PeerCertificate | null;
  authorized: boolean;
  authorizationError: string | null;
  /** Set when the connection never left the client — e.g. this Node/OpenSSL
   * build refuses to even offer a legacy protocol locally. Distinct from a
   * real network-level rejection, since it means the test is inconclusive
   * rather than a confirmed pass. */
  localError: string | null;
  connectError: string | null;
}

function handshake(target: SafeTarget, extraOptions: tls.ConnectionOptions, timeoutMs: number): Promise<HandshakeResult> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: HandshakeResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let socket: tls.TLSSocket;
    try {
      socket = tls.connect(
        {
          host: target.resolvedIp,
          servername: target.hostname, // SNI must be the hostname even though we dial the pinned IP
          port: target.port,
          timeout: timeoutMs,
          rejectUnauthorized: false, // we want to inspect+report invalid certs, not throw
          ...extraOptions,
        },
        () => {
          const cert = socket.getPeerCertificate();
          const authErr = (socket as tls.TLSSocket & { authorizationError?: Error | string | null }).authorizationError;
          finish({
            connected: true,
            protocol: socket.getProtocol(),
            cert: cert && Object.keys(cert).length > 0 ? cert : null,
            authorized: socket.authorized,
            authorizationError: authErr ? (authErr instanceof Error ? authErr.message : String(authErr)) : null,
            localError: null,
            connectError: null,
          });
          socket.end();
        }
      );
    } catch (err) {
      // Thrown synchronously by tls.connect() itself — e.g. this Node
      // build's OpenSSL security level refuses to even attempt the
      // requested protocol range locally, before any network I/O happens.
      finish({
        connected: false,
        protocol: null,
        cert: null,
        authorized: false,
        authorizationError: null,
        localError: err instanceof Error ? err.message : String(err),
        connectError: null,
      });
      return;
    }

    socket.on('error', (err) => {
      finish({
        connected: false,
        protocol: null,
        cert: null,
        authorized: false,
        authorizationError: null,
        localError: null,
        connectError: err.message,
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      finish({
        connected: false,
        protocol: null,
        cert: null,
        authorized: false,
        authorizationError: null,
        localError: null,
        connectError: 'timed out',
      });
    });
  });
}

export async function checkTls(target: SafeTarget): Promise<Finding[]> {
  if (target.protocol !== 'https:') {
    return [
      {
        id: 'tls-skipped',
        category: 'tls',
        title: 'TLS certificate check',
        severity: 'info',
        detail: 'Skipped — target is not served over HTTPS.',
        recommendation: 'Enable HTTPS to allow certificate validation.',
        passed: false,
      },
    ];
  }

  const findings: Finding[] = [];

  const primary = await handshake(target, {}, TIMEOUT_MS);

  if (!primary.connected) {
    findings.push({
      id: 'tls-connect-error',
      category: 'tls',
      title: 'TLS connection',
      severity: 'critical',
      detail: `Could not establish TLS connection: ${primary.connectError ?? primary.localError ?? 'unknown error'}`,
      recommendation: 'Confirm the server accepts TLS connections on this port.',
      passed: false,
    });
    return findings;
  }

  if (!primary.cert) {
    findings.push({
      id: 'tls-no-cert',
      category: 'tls',
      title: 'TLS certificate',
      severity: 'critical',
      detail: 'No certificate presented',
      recommendation: "Install a valid TLS certificate (e.g. via Let's Encrypt).",
      passed: false,
    });
    return findings;
  }

  const cert = primary.cert;

  // Chain-of-trust validity (was the cert signed by a CA Node trusts).
  findings.push({
    id: 'tls-validity',
    category: 'tls',
    title: 'Certificate validity',
    severity: primary.authorized ? 'pass' : 'critical',
    detail: primary.authorized
      ? `Valid, issued by ${cert.issuer?.O ?? cert.issuer?.CN ?? 'unknown issuer'}`
      : `Certificate is not trusted/valid (${primary.authorizationError ?? 'unknown reason'})`,
    recommendation: 'Install a certificate from a trusted CA and ensure the chain is complete.',
    passed: primary.authorized,
  });

  // Hostname/SAN match — a DISTINCT check from chain trust above.
  // rejectUnauthorized: false intentionally skips Node's automatic
  // checkServerIdentity() step (that's specifically what rejectUnauthorized
  // gates — not just whether the connection throws), so without calling it
  // explicitly here, a validly-CA-signed certificate for the WRONG hostname
  // (e.g. a default/fallback vhost cert on a misconfigured server) would
  // silently report as "Valid" even though every real browser would reject
  // it with a hostname-mismatch error. This is the actual browser-standard
  // check, run explicitly.
  const identityError = tls.checkServerIdentity(target.hostname, cert);
  findings.push({
    id: 'tls-hostname-match',
    category: 'tls',
    title: 'Certificate matches hostname',
    severity: identityError ? 'critical' : 'pass',
    detail: identityError ? identityError.message : `Certificate covers ${target.hostname}`,
    recommendation: 'Issue the certificate with the correct hostname in the Subject Alternative Name (SAN) list.',
    passed: !identityError,
  });

  const now = new Date();
  const validTo = new Date(cert.valid_to);
  const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

  if (Number.isNaN(daysRemaining)) {
    // cert.valid_to didn't parse as a date — every subsequent numeric
    // comparison against NaN is false, which would otherwise fall through
    // to the final (pass) branch below and silently claim "not expiring
    // soon" when expiry genuinely couldn't be determined. Report the
    // uncertainty instead of a confident-looking wrong answer.
    findings.push({
      id: 'tls-expiry',
      category: 'tls',
      title: 'Certificate expiry',
      severity: 'info',
      detail: `Could not parse the certificate's expiry date ("${cert.valid_to}").`,
      recommendation: 'Verify certificate expiry manually, e.g. `openssl s_client -connect host:443 | openssl x509 -noout -enddate`.',
      passed: true,
    });
  } else {
    findings.push({
      id: 'tls-expiry',
      category: 'tls',
      title: 'Certificate expiry',
      severity: daysRemaining < 0 ? 'critical' : daysRemaining < 14 ? 'high' : daysRemaining < 30 ? 'medium' : 'pass',
      detail: daysRemaining < 0 ? `Expired ${Math.abs(daysRemaining)} days ago` : `Expires in ${daysRemaining} days (${cert.valid_to})`,
      recommendation: 'Renew the certificate, and ideally automate renewal (e.g. certbot / ACME).',
      passed: daysRemaining >= 30,
    });
  }

  // Protocol version actually negotiated by a normal client — informative,
  // but NOT proof the server refuses weaker protocols (see below): Node's
  // default client only offers modern versions, so a server that would
  // happily downgrade for a client that DOES ask for TLS 1.0/1.1 negotiates
  // fine here regardless and would previously report a clean pass either way.
  findings.push({
    id: 'tls-protocol',
    category: 'tls',
    title: 'TLS protocol version (default negotiation)',
    severity: 'pass',
    detail: `Negotiated ${primary.protocol ?? 'unknown'} with a standard client.`,
    recommendation: 'No action needed.',
    passed: true,
  });

  // The check that actually matters: does the server accept a legacy
  // protocol if a client asks for one? Node's default TLS client won't
  // offer TLSv1.0/1.1 unless explicitly told to, so testing this requires
  // a second connection that deliberately requests only the weak range —
  // the same approach SSL Labs uses. Non-fatal to the overall scan if this
  // Node/OpenSSL build can't attempt it locally at all (common on OpenSSL
  // 3 builds with default @SECLEVEL) — that's reported as inconclusive,
  // never silently upgraded to a false "pass".
  const weakAttempt = await handshake(target, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1' }, WEAK_PROTOCOL_TEST_TIMEOUT_MS);

  if (weakAttempt.localError) {
    findings.push({
      id: 'tls-weak-protocol',
      category: 'tls',
      title: 'Legacy protocol (TLS 1.0/1.1) support',
      severity: 'info',
      detail: `Could not test — this scanner's TLS stack refused to attempt a legacy connection locally (${weakAttempt.localError}).`,
      recommendation: 'Test manually with a tool that supports forcing legacy protocol versions (e.g. `openssl s_client -tls1_1`) if this needs to be confirmed.',
      passed: true,
    });
  } else if (weakAttempt.connected) {
    findings.push({
      id: 'tls-weak-protocol',
      category: 'tls',
      title: 'Legacy protocol (TLS 1.0/1.1) support',
      severity: 'high',
      detail: `Server completed a handshake at ${weakAttempt.protocol ?? 'a legacy protocol'} when explicitly requested — it still accepts connections below TLS 1.2.`,
      recommendation: 'Disable TLS 1.0/1.1 and SSLv3 in the server/load-balancer config; require TLS 1.2 or higher (ideally 1.3 only).',
      passed: false,
    });
  } else {
    findings.push({
      id: 'tls-weak-protocol',
      category: 'tls',
      title: 'Legacy protocol (TLS 1.0/1.1) support',
      severity: 'pass',
      detail: 'Server refused a connection when only legacy protocol versions were offered.',
      recommendation: 'No action needed.',
      passed: true,
    });
  }

  return findings;
}
