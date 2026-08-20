# Aegis Scanner — MVP

A lead-gen security scanner: visitors scan a website or API for free, get a
teaser score, and unlock the full findings + fixes by leaving their email.
Built to be **agnostic** (checks work against any HTTP(S) target, not just
marketing sites) and hardened against the obvious ways a "fetch whatever URL
a stranger gives you" tool goes wrong.

## What's included

**Core scan engine** (`src/lib/scanner/`)
- Header checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, cookie flags, server/version info leakage, HTTP→HTTPS
- TLS: certificate validity, expiry countdown, protocol version (flags
  TLS 1.0/1.1/SSLv3)
- DNS: SPF, DMARC (+ policy strictness), MX
- Exposed paths: `.env`, `.git/config`, backup files, `server-status`,
  `phpinfo.php`, `security.txt` — passive GET requests only, no exploitation
- Scored 0–100 with an A–F letter grade

**Security hardening**
- **SSRF guard** (`src/lib/ssrfGuard.ts`) — resolves DNS itself, blocks
  private/loopback/link-local/reserved ranges and cloud metadata endpoints.
  Every outbound scan request goes through `pinnedFetch()`, an undici
  dispatcher whose custom `lookup` refuses to resolve anything but the
  exact IP already validated — this is what actually closes the
  DNS-rebinding gap (checking a hostname's IP once, then letting a later
  `fetch()` re-resolve it, would let a rebinding attacker swap in a private
  IP between the two lookups)
- **Rate limiting** (`src/lib/ratelimit.ts`) — 5 scans/hour + 20/day per IP,
  via Upstash Redis (falls back to in-memory for local dev only — not safe
  for multi-instance production)
- **Captcha** (`src/lib/captcha.ts`) — self-hosted stateless math challenge
  by default (zero config); swap to Cloudflare Turnstile by setting
  `CAPTCHA_PROVIDER=turnstile` before a public launch
- Timeouts on every outbound check; no raw response bodies stored, only
  specific finding values; security headers on the app itself
  (`next.config.js`)

**Zero-trust request handling**
- **Ownership acknowledgment** — a required checkbox on the scan form
  (`ownershipConfirmed`), recorded on the scan row
  (`ownership_acknowledged`, `ownership_ack_at`) as an audit trail. This is
  a legal/accountability control, not a technical one — it can't verify
  actual ownership. The SSRF guard, rate limiting, and captcha below are
  what actually constrain what gets scanned; the checkbox exists so
  there's a record of acknowledgment if a scan target ever disputes being
  scanned.
- **Input hardening on the URL field** — single line only (pasted
  multi-line text is collapsed to one line client-side; control
  characters/newlines are also rejected server-side via regex), capped at
  300 characters both client- and server-side.
- **Email trust checks** (`src/lib/emailTrust.ts`) — disposable/throwaway
  email domains are hard-blocked at lead-capture and monitor-signup time.
  Every email is also classified against the scanned domain
  (`domain_match` / `fuzzy_match` / `generic_provider` / `mismatch`, via
  registrable-domain comparison + Levenshtein similarity) and stored on the
  lead/monitor row (`email_trust`) — a soft signal for manual review, not a
  hard gate, since plenty of legitimate small businesses run their inbox on
  Gmail.
- **Non-gated routes reinforced** (`/api/lead`, `/api/monitor`) — these
  don't cost a scan, so previously they were protected by rate limiting
  alone. Both now also require their own captcha solve (via the shared
  `/api/captcha` endpoint), reject cross-origin submissions
  (`src/lib/originCheck.ts`), block disposable emails, and cap submissions
  per scan (`MAX_LEADS_PER_SCAN` in `/api/lead`).

**Scheduling — Supabase primary, Vercel fallback**
- `supabase/cron.sql` sets up pg_cron + pg_net to call `/api/cron/rescan`
  hourly, with the secret and app URL stored in Supabase Vault rather than
  inline in the job definition.
- `vercel.json`'s cron entry stays configured against the same endpoint,
  at the same hourly cadence, as a fallback in case pg_cron has an outage
  or the Supabase project is paused.
- Because two independent schedulers can now hit the same endpoint, the
  `monitors` table has claim-lock fields (`is_processing`,
  `processing_started_at`) and the cron handler claims due rows with a
  single atomic `UPDATE ... RETURNING` before processing them — so a
  monitor can't be re-scanned/double-emailed by both triggers firing close
  together. A lock older than 10 minutes is treated as stale and reclaimed
  (self-heals from a crashed run).

**Agnostic by design**
- Every check operates at the HTTP/TLS/DNS protocol level — nothing assumes
  HTML rendering. A REST/GraphQL API backend scans the same way a marketing
  site does. `targetType` (`web` | `api`) only changes report copy, not
  which checks run.
- DNS checks resolve to the correct registrable domain via `tldts`
  (`src/lib/domain.ts`), a real public-suffix-list implementation — handles
  `app.example.co.uk` → `example.co.uk`, `foo.github.io` → treated as its
  own registrable domain, etc., not just a "last two labels" guess.

**Part 3 improvement ideas — all included**
1. PDF export (`src/lib/pdf.ts`, `/api/report/[id]/pdf`)
2. Re-scan/historical tracking — every scan is stored by hostname, so score
   history is a query away; the cron job re-scans monitored sites
   automatically
3. Scheduled monitoring opt-in (`/api/monitor`, `/api/cron/rescan`) — free
   weekly/daily re-scan with an email alert on score change
4. Niche-aware results (`src/lib/scanner/niche.ts`) — tailored "why this
   matters" copy by business type, reusing the framing from direct outreach
5. Peer/industry benchmark (`src/lib/scanner/benchmark.ts`) — "businesses in
   this category average a B+"; only shown once a niche has 5+ samples
6. Shareable badge (`/api/badge/[id]`) — embeddable SVG grade badge linking
   back to the scanner
7. Slack/email digest (`src/lib/email.ts`) — real-time notification on every
   new lead

**SaaS/web-app specific checks (`src/lib/scanner/webapp.ts`, `webapp` category)**
- **CORS misconfiguration** — flags a wildcard/reflected-origin
  `Access-Control-Allow-Origin` combined with `Access-Control-Allow-Credentials:
  true` as critical (lets any site make authenticated requests on a logged-in
  user's behalf); a bare wildcard alone is flagged lower.
- **GraphQL introspection** — POSTs an introspection query to common
  `/graphql` paths; flags critical if the schema is publicly queryable.
- **Exposed API documentation** — checks common Swagger/OpenAPI paths.
- **Client-side secret scanning** — fetches up to 5 same-origin scripts
  referenced by the homepage and pattern-matches for AWS keys, Stripe live
  keys, Google API keys, Slack tokens, private key blocks, and generic
  long-string API-key assignments. Matched secrets are never included in
  the finding itself — only the pattern name and file, so the report can't
  become a second copy of the leaked credential.
- **Exposed source maps** — checks for a `.map` file alongside each script
  checked above; flags high since maps hand over full unminified source.
- **Subresource Integrity (SRI)** — flags third-party `<script>`/`<link>`
  tags on the homepage that load without an `integrity` attribute (supply-
  chain risk: a compromise at that third party becomes a full compromise of
  this site).
- **SaaS trust signals** (privacy policy link, terms link, cookie-consent
  tooling) — informational only, always `passed: true`, never affects the
  score. Compliance/sales signal, not a vulnerability.

All of the above use `pinnedFetch` against the same already-validated
target (same SSRF guarantees as every other check), are non-fatal to the
overall scan if any sub-check fails, and add a bounded number of requests
per scan (roughly +15-20 depending on how many same-origin scripts and
third-party resources a page has).

**Domain clone & phishing detection (gated)**
- Every scan automatically runs a lookalike/typosquat domain check
  (`src/lib/scanner/cloneDetection.ts`) — dnstwist-style permutations
  (omission, transposition, adjacent-key substitution, homoglyph
  substitution, hyphenation, TLD swap), bounded to ~120 candidates, resolved
  via DNS only (no HTTP fetch, no third-party API — cheap enough to run on
  every scan).
- Only the **count** of live/registered lookalike domains is ever shown for
  free (teaser and email-unlocked report both). The actual domain list, plus
  a deeper content-similarity search for cloned/mirrored copies of the site,
  is gated behind `/api/consult` — either a "Request consultation" button or
  an "Unlock instantly" paywall-intent button, both on the report page.
- The content-similarity search (`src/lib/scanner/contentSimilarity.ts`,
  optional Google Programmable Search Engine integration) is **only ever
  triggered by a consult/paywall submission** — never automatically —
  specifically to avoid an anonymous visitor burning a paid search API
  quota for free. It no-ops cleanly if `GOOGLE_CSE_API_KEY`/`GOOGLE_CSE_CX`
  aren't set.
- **Important:** "Unlock instantly" doesn't process real payment yet — it
  captures the same consult-request data with a `clone_report_paid_interest`
  tag so you can follow up/invoice manually. Wire in Stripe Checkout (or
  similar) in front of that button if you want a true self-serve unlock;
  the capture/notify/pre-fetch logic in `/api/consult` doesn't need to
  change either way.

**JS-rendered deep scan (gated, optional)**
- The free web-app checks parse the raw HTTP response — they can't see
  anything a client-rendered SPA injects into the DOM *after* that response
  (scripts added by JavaScript at runtime rather than present in the
  initial HTML). `src/lib/scanner/renderPage.ts` +
  `src/lib/scanner/deepScan.ts` fix this by rendering the page through a
  hosted headless-browser API (Browserless.io-compatible by default —
  `RENDER_API_URL`/`RENDER_API_KEY`) and re-running the DOM-dependent
  checks (client-side secrets, source maps, SRI, trust signals) against
  the resulting rendered HTML instead of the raw response.
- Triggered from `/api/consult` alongside the content-similarity search —
  same reasoning: rendering is materially slower (seconds, not
  milliseconds) and costs money per call on the hosted rendering service,
  so it never runs on the free/anonymous scan path. Gracefully no-ops if
  `RENDER_API_KEY` isn't set.
- The target URL still goes through the same SSRF guard as everywhere else
  before being handed to the rendering service — not because the service's
  own sandboxing can't be trusted, but so an obviously-internal-looking
  target never gets sent to a third party either.
- Results land in `consult_requests.deep_scan_status` /
  `deep_scan_findings`, tagged with `deep-` prefixed finding ids so
  they're never confused with the free-scan findings from the raw HTML
  pass if the two are ever displayed together.
- **Why not a self-hosted headless browser instead?** Considered and
  deliberately not built: bundling a real Chromium binary into a Vercel
  serverless function is workable (`@sparticuz/chromium` +
  `puppeteer-core`/`playwright-core`) but pushes close to function size
  limits, adds real cold-start latency, and — most importantly — a
  self-hosted browser executes the target page's JavaScript inside your
  own infrastructure's network context. That JavaScript can make its own
  outbound requests (to cloud metadata endpoints, internal IPs, etc.)
  independent of the initial navigation, which would need the SSRF guard
  reimplemented at the browser-request-interception level, not just the
  page-load level. The hosted-API approach pushes that surface onto the
  rendering provider instead, at the cost of a per-render fee and sending
  the scanned URL to a third party.

**Background work reliability on serverless (`waitUntil`)**
- `/api/lead` and `/api/consult` both kick off background work after
  responding (notifications, content-similarity search, deep scan) that
  shouldn't block the user-facing response. On Vercel (and serverless
  platforms generally), a bare un-awaited promise isn't guaranteed to
  finish — the function instance can be frozen or torn down shortly after
  the response is sent. Both routes wrap this background work in
  `waitUntil()` (from `@vercel/functions`) instead, which keeps the
  invocation alive until the promise settles, bounded by that route's
  `maxDuration`.
- `/api/consult` sets `maxDuration = 60` to give the rendering + search
  calls real room. Vercel's Hobby plan caps function duration at 10s
  regardless of this setting — the background work will get cut off on
  Hobby. Pro (or Fluid Compute) is effectively required for this to
  reliably complete; on Hobby, the consult request itself still succeeds
  (data is saved, notification usually gets through), but the
  content-similarity/deep-scan enrichment may not finish before cutoff.

## Setup

1. `npm install`
2. Copy `.env.example` to `.env.local` and fill in:
   - Supabase project URL + service role key
   - Upstash Redis REST URL + token (strongly recommended before public
     launch — see rate-limiting note above)
   - `CAPTCHA_HMAC_SECRET` — any long random string
   - Resend API key + `DIGEST_TO_EMAIL`/`DIGEST_FROM_EMAIL` for lead
     notifications and monitor alerts (optional but recommended)
   - `SLACK_WEBHOOK_URL` (optional, alternative/additional to email digest)
   - `CRON_SECRET` — any long random string, must match what your cron
     scheduler sends as `Authorization: Bearer <value>`
   - `APP_URL` — set this even in local dev; it's used for the
     same-origin check on `/api/lead` and `/api/monitor`
3. Run `supabase/schema.sql`, then `supabase/cron.sql`, in your Supabase SQL
   editor (in that order — `cron.sql` assumes the tables already exist).
   Edit the two `REPLACE_WITH_...` placeholders in `cron.sql` before
   running it.
4. (Optional) Set up `GOOGLE_CSE_API_KEY` + `GOOGLE_CSE_CX` if you want the
   content-similarity clone search to run — otherwise it's skipped cleanly.
5. (Optional) Set up `RENDER_API_KEY` (and `RENDER_API_URL` if not using
   Browserless.io) if you want the JS-rendered deep scan to run —
   otherwise it's skipped cleanly.
6. `npm run dev`

## Deploying (Vercel + Supabase)

- Supabase pg_cron is the primary scheduler (hourly) — see `supabase/cron.sql`.
- `vercel.json` keeps a fallback cron entry, at the same hourly cadence,
  hitting the same `/api/cron/rescan` endpoint, in case pg_cron/pg_net has
  an outage or the Supabase project gets paused (common on free-tier
  projects after a week of inactivity). Set `CRON_SECRET` in your Vercel
  project env vars — Vercel automatically attaches it as the Authorization
  header for cron-triggered requests.
  - Note: Vercel's Hobby plan only supports daily-granularity cron
    schedules, not the hourly/6-hourly ones in `vercel.json` — bump both
    to `"0 0 * * *"` if you're on Hobby, or upgrade to Pro. This doesn't
    matter much since Supabase is the primary path; it's a fallback.
- Set every var from `.env.example` in the Vercel dashboard.
- Before removing `CAPTCHA_PROVIDER=self`'s wheels: it's fine for launch,
  but if scan-spam becomes a problem, flip to Turnstile — no other code
  changes required.

## Known MVP limitations (fine to ship with, worth knowing)

- PDF text wrapping is naive (truncates rather than multi-line wraps very
  long strings) — findings/recommendations are written short enough that
  this rarely bites, but worth revisiting if you add longer copy.
- The self-hosted captcha stops casual bots, not a determined scripted
  attacker — that's an intentional tradeoff for zero-config launch, not an
  oversight. Move to Turnstile before a large marketing push.
- Exposed-path list is intentionally small (6 checks) per the "don't try to
  win on check-count" positioning in the original build doc — add more via
  `src/lib/scanner/exposedPaths.ts` if you find high-signal ones in outreach.
- Email trust classification is a heuristic signal (stored per lead/monitor
  for your own review), not a verification system — nothing stops someone
  from entering a real business email address they don't own. If that
  matters for your use case, add a double opt-in (confirm-by-click) step
  before a monitor's first alert goes out.
- No admin UI yet — lead status (`contacted`, `converted_to_client`) and
  the new `email_trust` column are queried directly in Supabase for now.
- Still not build-tested end-to-end (`npm run build`) in the environment
  this was written in — run that first before deploying.
- `next.config.js`'s CSP allows `'unsafe-eval'` in development only
  (`NODE_ENV !== 'production'`) — Next's dev server needs it for hot
  reload/source maps, or the app's JS gets blocked and the whole page
  silently fails to hydrate (forms fall back to native GET submission,
  event handlers never attach). Production builds don't get `unsafe-eval`
  and don't need it.
- The web-app checks (`webapp.ts`) parse HTML with regex rather than a real
  HTML parser — good enough for typical `<script src>`/`<link>` tags, but
  can miss unusual markup (attributes split across lines, dynamically
  injected tags that aren't in the initial HTML response at all — a
  client-rendered SPA's real script tags may only appear after JS runs,
  which this check won't see since it only looks at the raw HTML response).
- The client-side secret scan is pattern-based against a handful of common
  key formats — it will miss custom/internal secret formats and anything
  injected into the page after initial load. Treat a clean result as "no
  common patterns found," not "confirmed no secrets."
- GraphQL/API-doc/CORS checks only probe the small path lists defined in
  `webapp.ts` (`GRAPHQL_PATHS`, `API_DOC_PATHS`) — extend those arrays if
  you find other common paths worth checking during outreach.

## Advanced clone-detection stack (all gated — never runs on the free scan path)

- **DNS-permutation fixes** (`src/lib/scanner/cloneDetection.ts`):
  round-robin candidate generation (a long domain label can no longer
  silently starve the TLD-swap category the way the original ordering
  could), expanded homoglyphs, multi-char confusable pairs (rn→m, vv→w,
  cl→d, etc.), a real IDN/Unicode homograph pass (Cyrillic lookalikes),
  IPv4 **and** IPv6 resolution, retry-on-timeout (reduces false negatives
  from transient DNS jitter), and RDAP-based dormant-registration
  detection (`src/lib/dnsRdap.ts`) — catches a domain that's registered
  but not yet pointed anywhere, which DNS-only checking structurally
  cannot see. `CloneCandidate.registrationStatus` is `'active'` or
  `'registered_dormant'`.
- **Three parallel similarity techniques**
  (`src/lib/scanner/similarityOrchestrator.ts`), combined into one 0-1
  confidence score per candidate domain:
  - DOM structural fingerprinting (`domFingerprint.ts`) — free, simhash-
    based, catches verbatim phishing-kit copies (the dominant real
    pattern) even with reworded text.
  - Perceptual-hash screenshot comparison (`perceptualHash.ts`) — paid
    rendering API, catches visual clones that reworded/restyled the
    copied structure.
  - Google Vision reverse image search (`reverseImageSearch.ts`) — paid,
    finds matches anywhere on the web with no candidate-domain list
    needed at all; also surfaces clone domains the DNS-permutation
    approach could never have guessed.
  Each degrades independently — the free DOM comparison still
  contributes even if the paid API keys aren't configured.
- **Real Stripe payment** (`src/lib/stripe.ts`, `/api/stripe/checkout`,
  `/api/stripe/webhook`) replaces the earlier "captures intent, no real
  payment" stub. **Payment is only ever confirmed by the signature-
  verified webhook**, never by the client-side success redirect — Stripe
  Checkout Sessions are created for two products (`clone_report_unlock`,
  `domain_watch_subscription`), and `consult_requests.paid` /
  `clone_watch_subscriptions.paid` only flip to `true` inside
  `checkout.session.completed` handling after `stripe.webhooks.
  constructEvent()` verifies the signature.
- **Dormant-domain watch subscription** — pay once to be alerted the
  moment a currently-dormant lookalike domain goes live and scores within
  a chosen similarity range (default 70-90%) against the real site.
  `/api/cron/clone-watch` (Supabase pg_cron primary, Vercel fallback,
  same atomic-claim pattern as the existing rescan cron — see
  `clone_watch_subscriptions.is_processing`) periodically re-checks each
  paid subscription's dormant candidates; on a match it runs the full
  similarity analysis, emails an alert with an "escalate to consultant"
  link (auto-creates a `consult_requests` row), and deactivates the
  subscription (this is a one-time alert per payment, not a recurring
  billing model).
- The report page now explains, in plain language, why some lookalike
  domains show up with no live site behind them yet.

## Admin dashboard + magic-code login

- `/admin` — passwordless login: a 24-digit one-time numeric code emailed
  to a single hardcoded `ADMIN_EMAIL`. `/api/admin/request-code` is
  intentionally unauthenticated (you don't have a session yet) but safe:
  it never accepts a destination address from the caller, so it can't be
  used to spam or probe arbitrary inboxes — only to trigger a login
  attempt for the one configured admin identity. Only a salted hash of
  the code is ever stored (`admin_login_codes.code_hash`); requesting a
  new code invalidates any previous unused one. "Secured TCP handshake"
  for delivery is just TLS — the Resend API call happens over HTTPS,
  which *is* a secured TCP handshake; there's no separate protocol to
  build here.
- An authenticated admin session (signed, httpOnly, `SameSite=strict`
  cookie, `src/lib/adminAuth.ts`) **skips captcha and the ownership
  checkbox on `/api/scan`**, and **auto-unlocks every report** on
  `/api/report/[id]` without needing a lead/email captured first.
- `/api/admin/scans` lists past scans, filterable to `scope=mine` (scans
  whose recorded IP hash matches your current request IP — your own test
  scans) or `scope=all` (every scan, useful for reviewing real prospect
  activity).

## Mobile-first responsive + navigation

- `globals.css` was rewritten mobile-first: base rules target narrow
  viewports first (44-48px touch targets, stacked action buttons, 16px
  input font-size specifically to avoid iOS Safari's auto-zoom-on-focus
  behavior), with a single `min-width: 640px` media query layering on
  desktop enhancements — never the reverse.
- Back links added wherever a page didn't already have one (report page's
  unlocked view, the admin page).
- Lightweight persistent state: the scan form remembers the last-used URL
  and niche in `localStorage` across reloads. Convenience only — never
  stores anything sensitive, and never skips ownership/captcha
  re-confirmation.

## Additional setup for this round's features

1. Run the updated `supabase/schema.sql` (adds `clone_watch_subscriptions`,
   `admin_login_codes`, and new columns on `scans`/`consult_requests`) —
   safe to re-run on an existing database, every statement is
   `if not exists`/idempotent.
2. Add a second `cron.schedule()` call from the updated `supabase/cron.sql`
   for `/api/cron/clone-watch` (every 6 hours) — the file now has both.
3. `vercel.json` now has two cron entries; same Hobby-plan caveat as
   before (daily-only) applies to both.
4. Set `ADMIN_EMAIL` and a real `ADMIN_SESSION_SECRET` before deploying —
   `/admin` won't function without them (fails with a clear error, not
   silently).
5. Stripe: create two Products/Prices in your Stripe Dashboard (one for
   the clone-report unlock, one for the domain-watch subscription), set
   `STRIPE_PRICE_ID_CLONE_REPORT`/`STRIPE_PRICE_ID_DOMAIN_WATCH`
   accordingly, set `STRIPE_SECRET_KEY`, and register a webhook endpoint
   at `<your-domain>/api/stripe/webhook` listening for
   `checkout.session.completed` — Stripe will give you the
   `STRIPE_WEBHOOK_SECRET` when you create that endpoint. Without any of
   this configured, both paid buttons return a clear 503 rather than
   silently failing or fake-succeeding.
6. Google Vision: enable the Cloud Vision API in a GCP project, create an
   API key, set `GOOGLE_VISION_API_KEY`. First 1,000 units/month free,
   $3.50/1,000 after.

## Known limitations from this round (in addition to earlier ones above)

- **None of this has been through `npm run build` or a real Stripe test
  transaction.** Given how much surface accumulated this session — new
  dependencies (`sharp`, `stripe`, `@vercel/functions`), a real payment
  webhook, admin auth, two new cron jobs — running the build and a full
  Stripe test-mode checkout end-to-end before any real deploy matters more
  than usual here.
- The similarity-analysis candidate limit (`SIMILARITY_ANALYSIS_CANDIDATE_
  LIMIT` in `api/stripe/webhook/route.ts`) is 10 — bounds cost/time on
  what's now a paid feature, but means a scan with more than 10 lookalike
  candidates only gets the deepest analysis on the first 10.
- The DOM-fingerprint and perceptual-hash comparisons fetch/render the
  *target's* raw HTML/screenshot fresh on every comparison rather than
  reusing what the original scan already fetched — fine for the current
  bounded-candidate-count, worth revisiting if candidate counts grow.
- `sharp` (used for perceptual hashing) needs native binaries — this
  generally works fine on Vercel's Node runtime out of the box, but is
  worth explicitly verifying in your build logs the first time you deploy
  this, since native-dependency issues are exactly the kind of thing that
  works locally and breaks on a different platform/architecture.
- The admin "my scans" filter matches on IP-hash equality, so it only
  shows scans run from whatever network you're currently on when you view
  the dashboard — scanning from a different IP (different wifi, VPN on/off,
  mobile data) means "my scans" won't show earlier sessions from a
  different network. "All scans" always shows everything regardless.

## This round: full admin supersede, 4-tab navigation, fix-it-yourself unlock, idle timeout

**Admin now supersedes every gate, including payment**
- `/api/lead`, `/api/monitor`, `/api/consult`, `/api/stripe/checkout` all
  check `isAdminRequest()` (`src/lib/adminAuth.ts`) and skip captcha, rate
  limiting, and the disposable-email block for an authenticated admin
  session.
- `/api/stripe/checkout` has a genuine admin direct-grant path: for an
  admin session, it never creates a Stripe session at all — it marks the
  underlying row (`consult_requests.paid`, `clone_watch_subscriptions.paid`
  +`active`, or `fix_guide_purchases.paid`) `true` directly and returns
  `{ adminGranted: true }`. The frontend detects this and skips the Stripe
  redirect, fetching the unlocked content immediately instead.
- **Deliberately NOT bypassed for admin sessions: origin/CSRF checking.**
  A forged cross-site request riding on the admin's own authenticated
  cookie is exactly the scenario Origin checking exists to catch —
  admin status should never weaken that specific protection, even though
  it supersedes everything else.

**Four-tab navigation** (`src/components/TopNav.tsx`)
- **Web Scans** (`/`) — the original scan form, `targetType` defaults to `web`.
- **SaaS Scans** (`/saas`) — same form (extracted into
  `src/components/ScanForm.tsx`, parameterized), `targetType` defaults to
  `api`, copy emphasizes the SaaS-specific checks (CORS, GraphQL,
  secrets, source maps, SRI).
- **Compliance** (`/compliance`) — coming-soon placeholder.
- **Consulting** (`/consulting`) — details everything Aegis offers (free
  scans, gated clone detection, the fix-it-yourself unlock, and the
  consulting service itself), with the differentiator stated plainly: a
  scan tells you what's wrong, a consult fixes it. Has its own contact
  form wired to `/api/consult` with `requestType: 'general'` and no
  `scanId` — `/api/consult`'s scan lookup and clone-specific background
  work are now both conditional on a `scanId` actually being present, so
  a general inquiry from this page doesn't require (or waste API calls
  on) a prior scan.

**Fix-it-yourself paid unlock**
- `src/lib/scanner/fixProcedures.ts` — real step-by-step remediation
  content (not just the free report's one-line recommendation), keyed by
  finding id, with a generic fallback for anything not explicitly covered.
- Served only by `/api/report/[id]/fix-guide` — **never included in
  `/api/report/[id]`'s response, paid or not.** This was a hard
  requirement (fully gated, never printed as part of the report), so it's
  architecturally a separate endpoint rather than a conditional field on
  the main report, removing any risk of a future edit accidentally
  leaking it into the free path.
- Gated on `fix_guide_purchases.paid = true` or an admin session.

**Idle timeout (client-side only — never touches stored data)**
- `src/hooks/useIdleTimeout.ts` — generic activity-based idle hook.
- The report page clears its currently-displayed state after 10 minutes
  of inactivity and shows a "session paused" screen. The underlying
  database row is completely untouched — this is a privacy measure for a
  screen left open and unattended, not a data-retention mechanism.
- Re-entering the email that originally unlocked the report
  (`/api/report/[id]/resume`) restores the view — a lightweight check
  (does this email match an existing lead for this scan?) rather than a
  full re-authentication system, matching the "some sort of persistence
  stays" requirement without building session infrastructure the rest of
  the app doesn't otherwise have.

## Setup additions for this round

1. Re-run `supabase/schema.sql` (adds `fix_guide_purchases`, and
   `consult_requests.request_type` now also accepts `'general'`) —
   idempotent, safe to re-run.
2. Create a third Stripe Price for the fix-guide unlock, set
   `STRIPE_PRICE_ID_FIX_GUIDE`.
3. No new pages need manual wiring — `/saas`, `/compliance`, and
   `/consulting` are already linked from `TopNav` on every tab.

## Known limitations from this round

- **Still not build-tested.** This round touched five existing routes
  (admin bypass), added a new Stripe product end-to-end, and added four
  new pages plus a large addition to the report page — run `npm run
  build` before anything else, more than ever at this point in the
  project.
- The idle-timeout "resume" check is intentionally lightweight (email
  match against `leads`, not a real session) — it deters casual re-viewing
  by someone who doesn't know the unlocking email, but it's not a strong
  access control. Fine for the stated purpose (a shared-screen privacy
  nicety), not a substitute for real per-viewer authentication if that's
  ever needed.
- The Consulting page's marketing copy is generic placeholder content
  ("typical engagements," etc.) — written to be structurally correct and
  ready to wire up, but you'll want to replace it with your actual
  pricing/positioning before this goes live to real prospects.
