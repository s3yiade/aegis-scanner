/**
 * Detailed, step-by-step fix procedures for findings — the "fix yourself"
 * paid unlock. The free report's `recommendation` field on each Finding
 * is intentionally a one-liner; this is the actual walkthrough. Keyed by
 * Finding.id so it stays in sync with whatever check produced the finding.
 *
 * IMPORTANT: this module's content must never be imported by anything
 * that serves the free/email-gated report — only
 * api/report/[id]/fix-guide, which checks payment/admin status first.
 */

export interface FixProcedure {
  title: string;
  steps: string[];
  estimatedTime: string;
}

const PROCEDURES: Record<string, FixProcedure> = {
  hsts: {
    title: 'Add HTTP Strict Transport Security',
    estimatedTime: '10-15 minutes',
    steps: [
      'Decide on a max-age — 63072000 (2 years) is the standard recommendation once you\'re confident HTTPS works everywhere on the domain.',
      'Add the header at your web server or reverse proxy: Strict-Transport-Security: max-age=63072000; includeSubDomains',
      'If every subdomain is also served over HTTPS, keep includeSubDomains; if not, remove it or fix those subdomains first — this header applies browser-side and will break HTTP-only subdomains for visitors.',
      'Once stable for a few weeks, consider adding preload and submitting to hstspreload.org for browser-baked-in enforcement — this is a one-way door (hard to reverse), so don\'t rush it.',
      'Verify with curl -I https://yourdomain.com | grep -i strict-transport, or securityheaders.com.',
    ],
  },
  csp: {
    title: 'Add a Content Security Policy',
    estimatedTime: '1-3 hours (more if the site has many third-party scripts)',
    steps: [
      'Start in report-only mode so nothing breaks: Content-Security-Policy-Report-Only header instead of the enforcing one.',
      'Begin with a strict baseline: default-src \'self\'; then add exceptions only for what you actually load (fonts, analytics, payment widgets, etc.).',
      'Open the site with browser dev tools open and watch the console for CSP violation reports — each one tells you exactly what to add.',
      'Avoid \'unsafe-inline\' and \'unsafe-eval\' if at all possible — if inline scripts are unavoidable, use a nonce or hash instead.',
      'Once no violations show up in report-only mode over a normal usage cycle, switch to the enforcing Content-Security-Policy header.',
      'Re-test the whole site (forms, checkout flow, third-party widgets) after switching to enforcing mode — report-only mode doesn\'t always catch everything a real user would hit.',
    ],
  },
  'x-frame-options': {
    title: 'Prevent clickjacking',
    estimatedTime: '5 minutes',
    steps: [
      'Add X-Frame-Options: DENY at your web server (or SAMEORIGIN if you legitimately need to frame your own pages from your own domain).',
      'If you already have a CSP, frame-ancestors \'none\' does the same job and is the more modern approach — you can use either or both.',
      'Verify: try embedding the page in an <iframe> on a different domain and confirm it refuses to load.',
    ],
  },
  'content-type-options': {
    title: 'Stop MIME-sniffing',
    estimatedTime: '5 minutes',
    steps: [
      'Add X-Content-Type-Options: nosniff at your web server for all responses.',
      'Double check any endpoints serving user-uploaded files have the correct Content-Type set explicitly — nosniff means the browser trusts whatever Content-Type you send instead of guessing, so an incorrect one will now actually matter.',
    ],
  },
  'referrer-policy': {
    title: 'Add a Referrer-Policy',
    estimatedTime: '5 minutes',
    steps: [
      'Add Referrer-Policy: strict-origin-when-cross-origin — a good default that keeps full referrer info for same-origin requests but trims it to just the origin for cross-origin ones.',
      'If any URLs on the site contain sensitive data (tokens, IDs) in the path or query string, consider the stricter same-origin or no-referrer instead.',
    ],
  },
  'info-leak': {
    title: 'Stop leaking server/version information',
    estimatedTime: '15-30 minutes (varies by stack)',
    steps: [
      'Nginx: add server_tokens off; in your http block.',
      'Apache: set ServerTokens Prod and ServerSignature Off in your config.',
      'Express/Node: app.disable(\'x-powered-by\') removes the X-Powered-By header.',
      'For any framework-specific headers (e.g. a CMS revealing its exact plugin versions), check that framework\'s hardening guide — the general principle is the same: don\'t hand attackers your exact stack version for free.',
    ],
  },
  'cookie-flags': {
    title: 'Secure your cookies',
    estimatedTime: '15-30 minutes',
    steps: [
      'For every cookie your application sets — especially session/auth cookies — add: Secure (only sent over HTTPS), HttpOnly (not readable by JavaScript, blocks a whole class of XSS-driven session theft), and SameSite=Lax or Strict (blocks most CSRF).',
      'If using a framework, this is usually a session-config setting rather than manual header-writing — e.g. Express-session\'s cookie: { secure: true, httpOnly: true, sameSite: \'lax\' }.',
      'Consider cookie name prefixes (__Host- or __Secure-) for extra browser-enforced guarantees on your most sensitive cookies.',
    ],
  },
  'no-https': {
    title: 'Move to HTTPS-only',
    estimatedTime: '1-2 hours (mostly waiting on cert issuance/DNS)',
    steps: [
      'Get a certificate — Let\'s Encrypt (free, automatable via certbot) covers the vast majority of cases.',
      'Configure your web server to serve HTTPS on 443 with the new certificate.',
      'Add a redirect from every HTTP request to the HTTPS equivalent (a 301 redirect at the web server level, not an application-level one).',
      'Set up auto-renewal (certbot does this by default via a cron job/systemd timer) — an expired cert is a self-inflicted outage.',
      'Once confirmed stable, follow the HSTS procedure above to force HTTPS at the browser level too.',
    ],
  },
  'tls-expiry': {
    title: 'Renew your TLS certificate',
    estimatedTime: '15-30 minutes',
    steps: [
      'If using Let\'s Encrypt/certbot, run certbot renew manually first to confirm it works, then verify the auto-renewal cron/systemd timer is actually enabled and running.',
      'If using a commercial CA, renew through their portal and reinstall the new certificate at your web server/load balancer.',
      'Set a calendar reminder well before the new expiry date regardless — don\'t rely solely on automation for something this disruptive if it fails silently.',
    ],
  },
  'tls-protocol': {
    title: 'Disable outdated TLS versions',
    estimatedTime: '15-30 minutes',
    steps: [
      'Nginx: ssl_protocols TLSv1.2 TLSv1.3; in your server block (drop TLSv1 and TLSv1.1 entirely).',
      'Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3.',
      'Restart/reload the web server and re-test with the scanner or ssllabs.com/ssltest.',
      'If you have legacy clients that genuinely require TLS 1.0/1.1, that\'s a separate conversation about accepted risk — don\'t re-enable them by default to fix a compatibility complaint without weighing that tradeoff explicitly.',
    ],
  },
  spf: {
    title: 'Publish an SPF record',
    estimatedTime: '15-20 minutes',
    steps: [
      'List every service that legitimately sends email as your domain (your mail provider, any marketing/transactional email tool, etc.).',
      'Build the SPF TXT record, e.g.: v=spf1 include:_spf.yourmailprovider.com -all',
      'Add it as a TXT record on the apex domain (not a subdomain) via your DNS provider.',
      'End with -all (hard fail) once you\'re confident the include list is complete — start with ~all (soft fail) if you want a safety margin while testing.',
      'Verify with a lookup tool like mxtoolbox.com/spf.aspx.',
    ],
  },
  dmarc: {
    title: 'Publish a DMARC record',
    estimatedTime: '20-30 minutes, plus a monitoring period before tightening',
    steps: [
      'Start in monitor-only mode: add a TXT record at _dmarc.yourdomain.com with v=DMARC1; p=none; rua=mailto:you@yourdomain.com',
      'Let it run for 1-2 weeks and review the aggregate reports sent to your rua address — these show you every source claiming to send mail as your domain, including your own legitimate services.',
      'Once you\'ve confirmed SPF/DKIM pass for all legitimate senders, move to p=quarantine, then eventually p=reject for full enforcement.',
      'This is one of the highest-impact fixes on this list for stopping domain-spoofing phishing — worth prioritizing even though it takes a monitoring period to do safely.',
    ],
  },
  cors: {
    title: 'Fix CORS configuration',
    estimatedTime: '30-60 minutes',
    steps: [
      'Never combine Access-Control-Allow-Origin: * (or a reflected arbitrary origin) with Access-Control-Allow-Credentials: true — this combination lets any website make authenticated requests on a logged-in user\'s behalf and read the response.',
      'Replace the wildcard/reflection with an explicit allow-list of trusted origins your frontend actually runs on.',
      'Most frameworks have a CORS middleware with an origin allow-list option (e.g. Express\'s cors package, Django\'s CORS_ALLOWED_ORIGINS) — use that rather than hand-rolling header logic.',
      'Re-test every legitimate cross-origin flow (if you have one) after tightening — a too-strict allow-list breaks things just as surely as a too-loose one leaks them.',
    ],
  },
  'graphql-introspection': {
    title: 'Disable GraphQL introspection in production',
    estimatedTime: '15-30 minutes',
    steps: [
      'Most GraphQL server libraries have a one-line flag for this — e.g. Apollo Server: introspection: false in production config; graphql-yoga and others have equivalents.',
      'Keep introspection enabled in development/staging environments where your own team needs it for tooling (GraphiQL, codegen, etc.) — just not in production.',
      'If you use introspection-dependent tooling in production (e.g. an internal admin GraphiQL), put it behind authentication rather than leaving the whole endpoint open.',
      'Re-run the check after deploying to confirm the introspection query now fails.',
    ],
  },
  'api-docs-exposed': {
    title: 'Review exposed API documentation',
    estimatedTime: '15-30 minutes',
    steps: [
      'Decide whether this API is meant to be public — if it\'s a public/partner API, exposed docs may be entirely intentional; skip the rest of this if so.',
      'If it\'s meant to be internal, put the docs endpoint behind authentication (even a simple shared secret/basic auth is far better than nothing).',
      'Check whether the docs themselves reveal anything beyond endpoint shapes — internal hostnames, example credentials left in sample requests, etc. — and scrub those regardless of whether you gate the endpoint.',
    ],
  },
  'client-secrets': {
    title: 'Remove and rotate exposed secrets',
    estimatedTime: 'Rotation: 15-30 min per credential. Fix: 1-3 hours depending on how deeply embedded the pattern is.',
    steps: [
      'Treat every matched credential as compromised immediately — rotate it at the provider (AWS IAM, Stripe dashboard, etc.) regardless of how old the deployed code is; assume it\'s been scraped already.',
      'Find every place the secret is used server-side and move it to an environment variable, not a build-time constant that gets bundled into client JS.',
      'Audit your build process — a common cause is a bundler accidentally including server-only config in a client bundle (e.g. importing a shared config file that happens to contain both public and secret keys).',
      'Add a pre-commit or CI secret-scanning step (many free options: gitleaks, trufflehog) so this doesn\'t silently happen again.',
      'Re-run the scan after deploying the fix to confirm the pattern no longer matches.',
    ],
  },
  'source-maps': {
    title: 'Remove exposed source maps from production',
    estimatedTime: '15-30 minutes',
    steps: [
      'Most bundlers (webpack, Vite, esbuild, Next.js) have a production build flag to skip generating source maps entirely, or to generate them without publishing the .map file to your public output directory.',
      'If you want source maps for your own error-tracking tool (e.g. Sentry), upload them directly to that tool as a build step instead of serving them publicly — most error trackers support this natively.',
      'If maps must stay in the build output for some reason, add a web-server rule blocking public access to *.map files.',
    ],
  },
  sri: {
    title: 'Add Subresource Integrity to third-party resources',
    estimatedTime: '20-40 minutes',
    steps: [
      'For each third-party <script>/<link> tag, get the integrity hash — most CDNs (cdnjs, jsDelivr) show the correct integrity attribute right on their site alongside the script tag to copy.',
      'Add both integrity="sha384-..." and crossorigin="anonymous" to the tag — both are required together for SRI to work.',
      'If you self-host a copy instead of relying on a CDN, you eliminate this specific risk entirely at the cost of manually tracking updates yourself — a reasonable tradeoff for a small number of critical scripts.',
      'Remember to update the integrity hash any time you intentionally update the third-party script\'s version — a stale hash will just block the (now different) legitimate file too.',
    ],
  },
  'exposed:/.env': {
    title: 'Remove exposed .env file',
    estimatedTime: '30-60 minutes (mostly credential rotation)',
    steps: [
      'Rotate every credential in the file immediately — database passwords, API keys, session secrets — assume all of them are compromised.',
      'Move .env out of the public web root, or add a web-server rule blocking access to dotfiles (deny access to any path starting with a dot).',
      'Check your deployment process for how it ended up publicly served — often it\'s a missing .gitignore entry combined with a build step that copies the whole repo into the public directory.',
      'Add automated secret scanning to your CI pipeline to catch this class of mistake before it deploys again.',
    ],
  },
  'exposed:/.git/config': {
    title: 'Remove exposed .git directory',
    estimatedTime: '30-60 minutes',
    steps: [
      'Block access to /.git/ at the web server level immediately — this is the highest priority since a full .git directory often allows reconstructing your entire source history, including anything ever committed (even if later removed).',
      'Audit git history for anything sensitive that was ever committed (credentials, internal URLs, etc.) — if found, rotate those credentials too, since removing a file from a later commit doesn\'t remove it from history.',
      'Fix your deployment process so the .git directory never ends up inside the public web root in the first place — typically this means deploying a build artifact, not a raw checkout of the repository.',
    ],
  },
};

const GENERIC_FALLBACK: FixProcedure = {
  title: 'General remediation approach',
  estimatedTime: 'Varies',
  steps: [
    'Confirm the finding by re-checking it manually (browser dev tools network tab for headers, or the specific tool relevant to the finding type).',
    'Identify where in your stack the fix belongs — web server config, application code, or a third-party service setting.',
    'Make the change in a staging environment first if you have one, and re-verify before deploying to production.',
    'Re-run this scan after deploying to confirm the finding clears.',
  ],
};

export function getFixProcedure(findingId: string): FixProcedure {
  // Strip a 'deep-' prefix (see deepScan.ts) so the same procedure applies
  // whether the finding came from the free scan or the JS-rendered deep scan.
  const baseId = findingId.replace(/^deep-/, '');
  return PROCEDURES[baseId] ?? GENERIC_FALLBACK;
}
