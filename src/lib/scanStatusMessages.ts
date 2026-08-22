/**
 * Status messages shown one at a time in the scanning dialog (see
 * components/ScanningDialog.tsx) while a scan is in flight. Ordered to
 * roughly follow the actual execution order in lib/scanner/index.ts, so
 * someone watching it cycle is seeing something close to the truth rather
 * than decorative filler — every check named here is a real check that
 * runs on every scan (see the corresponding file in lib/scanner/).
 *
 * The scan runs the same full check suite regardless of which page it was
 * started from (web vs API/SaaS — see the "Agnostic by design" note in
 * lib/scanner/index.ts), so this single list covers every scan.
 */
export const SCAN_STATUS_MESSAGES: string[] = [
  'Establishing a safe connection to the target…',
  'Attempting header validity check…',
  'Checking HSTS, CSP & clickjacking protection…',
  'Validating TLS certificate & protocol version…',
  'Attempting DMARC validation…',
  'Checking SPF & MX records…',
  'Probing for subdomain takeover…',
  'Sweeping for exposed .env / .git / backup files…',
  'Testing CORS policy for credentialed access…',
  'Probing GraphQL introspection…',
  'Checking for exposed API documentation…',
  'Scanning client-side scripts for leaked secrets…',
  'Checking for exposed source maps…',
  'Auditing third-party script integrity (SRI)…',
  'Enumerating allowed HTTP methods…',
  'Checking for verbose error disclosure…',
  'Testing Host header trust…',
  'Probing for open redirects…',
  'Checking endpoint access control…',
  'Testing rate-limit behavior…',
  'Running lookalike-domain sweep…',
  'Compiling findings & scoring…',
];
