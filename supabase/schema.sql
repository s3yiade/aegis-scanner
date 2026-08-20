-- Aegis Scanner schema
-- Run in Supabase SQL editor. Uses RLS with service-role-only writes;
-- the app only ever talks to Supabase from the server (service role key),
-- never from the browser, so RLS is set to deny-all for anon/public.

create extension if not exists pgcrypto;

create table if not exists scans (
  id uuid primary key default gen_random_uuid(),
  target_url text not null,
  hostname text not null,
  target_type text not null default 'web' check (target_type in ('web', 'api')),
  score int not null,
  grade text not null,
  findings jsonb not null,
  niche text, -- e.g. 'jewelry', 'ecommerce', 'professional_services', null = generic
  scanned_at timestamptz not null default now(),
  ip_address text, -- hashed, see lib/ratelimit.ts; used for abuse investigation only
  -- Zero-trust framing: this is an audit trail, not a technical control —
  -- the checkbox itself can't stop anyone. See lib/originCheck.ts and the
  -- SSRF guard for the checks that actually constrain what gets scanned.
  ownership_acknowledged boolean not null default false,
  ownership_ack_at timestamptz,
  -- Lookalike/clone-domain scan (see lib/scanner/cloneDetection.ts). Runs
  -- automatically on every scan since it's DNS-only and cheap; only the
  -- count is ever shown pre-consult — the domain list itself is gated
  -- behind a consult request or paywall (see consult_requests below).
  clone_candidates jsonb,
  clone_candidate_count int not null default 0,
  clone_scan_status text not null default 'pending' check (clone_scan_status in ('pending', 'complete', 'failed'))
);

create index if not exists idx_scans_hostname on scans (hostname);
create index if not exists idx_scans_scanned_at on scans (scanned_at desc);
-- Supports refreshNicheBenchmark's per-niche, rolling-90-day query (see
-- lib/scanner/benchmark.ts), run once per active niche on every cron
-- cycle — without this, that's a full-table scan on every run.
create index if not exists idx_scans_niche_scanned_at on scans (niche, scanned_at) where niche is not null;

create table if not exists leads (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid references scans(id) on delete set null,
  name text,
  email text not null,
  business_type text,
  -- 'domain_match' | 'fuzzy_match' | 'generic_provider' | 'mismatch' — see
  -- lib/emailTrust.ts. A signal for manual review, never a hard gate here
  -- (disposable addresses are the only hard block, at submission time).
  email_trust text,
  created_at timestamptz not null default now(),
  contacted boolean default false,
  converted_to_client boolean default false
);

create index if not exists idx_leads_email on leads (email);
create index if not exists idx_leads_scan_id on leads (scan_id);

-- Scheduled monitoring opt-ins (Part 3 idea #3 — free-tier version of the Monitor retainer)
create table if not exists monitors (
  id uuid primary key default gen_random_uuid(),
  hostname text not null,
  target_url text not null,
  email text not null,
  email_trust text, -- see lib/emailTrust.ts
  active boolean not null default true,
  frequency text not null default 'weekly' check (frequency in ('weekly', 'daily')),
  last_scan_id uuid references scans(id) on delete set null,
  last_score int,
  created_at timestamptz not null default now(),
  next_run_at timestamptz not null default (now() + interval '7 days'),
  unsubscribe_token uuid not null default gen_random_uuid(),
  -- Claim-lock fields: the rescan cron can now be triggered from both
  -- Supabase pg_cron (primary) and Vercel Cron (fallback), which can fire
  -- close together. These let the cron handler atomically claim a batch of
  -- due rows in one UPDATE...RETURNING so both triggers can't process the
  -- same monitor twice. A stale lock (crashed mid-run) self-heals after 10
  -- minutes — see api/cron/rescan.
  is_processing boolean not null default false,
  processing_started_at timestamptz
);

create index if not exists idx_monitors_next_run on monitors (next_run_at) where active = true;
create unique index if not exists idx_monitors_hostname_email on monitors (hostname, email);

-- Peer/industry benchmark aggregates (Part 3 idea #5), refreshed periodically
-- rather than computed live over the full scans table.
create table if not exists niche_benchmarks (
  niche text primary key,
  avg_score numeric not null,
  avg_grade text not null,
  sample_size int not null,
  updated_at timestamptz not null default now()
);

-- Currently unused: lib/ratelimit.ts's non-Redis fallback is an in-process
-- Map, not this table (which would be safer across serverless instances
-- but isn't wired up). Kept for a future migration to a real DB-backed
-- fallback; not read or written by any code path today.
create table if not exists rate_limit_events (
  id bigserial primary key,
  ip_hash text not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_rate_limit_ip_time on rate_limit_events (ip_hash, created_at);

-- Consult / paywall requests for the gated clone-detection deep dive
-- (full lookalike-domain list + content-similarity search results).
-- Neither reveal happens automatically for anonymous visitors — this table
-- is the trigger that kicks off the (potentially paid-API-backed) content
-- similarity search and marks intent for follow-up.
create table if not exists consult_requests (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid references scans(id) on delete set null,
  email text not null,
  name text,
  -- 'clone_report' = "contact me" consult request.
  -- 'clone_report_paid_interest' = clicked the paywall-unlock button. No
  -- payment is actually processed yet (see lib/consultRequest.ts) — this
  -- captures intent so you can follow up/invoice manually, or wire in a
  -- real payment processor later without changing the capture flow.
  request_type text not null default 'clone_report' check (request_type in ('clone_report', 'clone_report_paid_interest', 'general')),
  email_trust text, -- see lib/emailTrust.ts
  message text,
  created_at timestamptz not null default now(),
  contacted boolean default false,
  -- Populated asynchronously after the content-similarity search runs
  -- (only triggered by a request landing here, never automatically).
  content_similarity_status text not null default 'pending' check (content_similarity_status in ('pending', 'complete', 'skipped_no_api_key', 'failed')),
  content_similarity_matches jsonb,
  -- Populated asynchronously after the JS-rendered deep scan runs (see
  -- lib/scanner/deepScan.ts) — re-checks client-side secrets, source maps,
  -- SRI, and trust signals against the DOM after JavaScript executes,
  -- catching what a client-rendered SPA injects post-load. Same trigger
  -- and gating as content_similarity above.
  deep_scan_status text not null default 'pending' check (deep_scan_status in ('pending', 'complete', 'skipped_no_api_key', 'failed')),
  deep_scan_findings jsonb,
  -- Stripe payment tracking for the 'clone_report_paid_interest' path —
  -- see api/stripe/checkout and api/stripe/webhook. paid stays false until
  -- Stripe's webhook confirms checkout.session.completed; never set it
  -- true anywhere else (never trust the client-side redirect alone).
  paid boolean not null default false,
  stripe_session_id text,
  -- Similarity results computed by lib/scanner/similarityOrchestrator.ts
  -- (DOM fingerprint + perceptual hash + reverse image search, run in
  -- parallel) against the clone_candidates already found for this scan.
  similarity_status text not null default 'pending' check (similarity_status in ('pending', 'complete', 'failed')),
  similarity_results jsonb
);

create index if not exists idx_consult_requests_scan_id on consult_requests (scan_id);

-- Dormant-domain watch: pay to be alerted the moment a currently-dormant
-- lookalike domain (registered but not yet resolving — see
-- registrationStatus in cloneDetection.ts) goes live AND scores within a
-- given similarity range against the target. This is what actually
-- addresses "a threat actor registers a domain and sits on it until the
-- clone is ready" — the free scan can only tell you dormant candidates
-- exist right now; this subscription is what watches them over time.
create table if not exists clone_watch_subscriptions (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid references scans(id) on delete set null,
  hostname text not null,
  email text not null,
  email_trust text,
  similarity_min int not null default 70,
  similarity_max int not null default 90,
  -- Mirrors consult_requests.paid — stays false until Stripe confirms
  -- payment via webhook. active is separate: a paid subscription that's
  -- been fulfilled (alert sent) or manually cancelled can be set inactive
  -- without touching the payment record.
  paid boolean not null default false,
  active boolean not null default false,
  stripe_session_id text,
  created_at timestamptz not null default now(),
  last_checked_at timestamptz,
  unsubscribe_token uuid not null default gen_random_uuid(),
  -- Same atomic-claim pattern as monitors.is_processing — see
  -- api/cron/rescan for the full reasoning (two independent schedulers,
  -- Supabase pg_cron primary + Vercel fallback, can fire close together).
  is_processing boolean not null default false,
  processing_started_at timestamptz
);

create index if not exists idx_clone_watch_active on clone_watch_subscriptions (active) where active = true and paid = true;

-- Admin magic-code login (see lib/adminAuth.ts). Single hardcoded admin
-- identity (ADMIN_EMAIL env var) — this table just tracks the current
-- one-time code, never a password or long-lived credential. Only the hash
-- is stored, never the plaintext code.
create table if not exists admin_login_codes (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null,
  expires_at timestamptz not null,
  used boolean not null default false,
  created_at timestamptz not null default now()
);

create index if not exists idx_admin_codes_expiry on admin_login_codes (expires_at);

-- Paid "fix it yourself" unlock: detailed step-by-step remediation
-- procedures for a scan's findings (see lib/scanner/fixProcedures.ts).
-- Deliberately its own table, not folded into consult_requests — this is
-- about the whole report's findings, not specifically clone detection.
-- The procedures themselves are NEVER included in /api/report/[id]'s
-- response, paid or not; they're only ever served by
-- /api/report/[id]/fix-guide, which checks this table (or an admin
-- session) before returning anything.
create table if not exists fix_guide_purchases (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid references scans(id) on delete set null,
  email text not null,
  email_trust text,
  paid boolean not null default false,
  stripe_session_id text,
  created_at timestamptz not null default now()
);

create index if not exists idx_fix_guide_scan_id on fix_guide_purchases (scan_id);

alter table scans enable row level security;
alter table leads enable row level security;
alter table monitors enable row level security;
alter table niche_benchmarks enable row level security;
alter table rate_limit_events enable row level security;
alter table consult_requests enable row level security;
alter table clone_watch_subscriptions enable row level security;
alter table admin_login_codes enable row level security;
alter table fix_guide_purchases enable row level security;
-- No policies are created: with RLS enabled and zero policies, every table is
-- fully inaccessible to the anon/public roles. Only the service-role key
-- (server-side only, never shipped to the browser) can read/write.

-- ---------------------------------------------------------------------
-- Migrations for already-provisioned databases. Everything above is
-- idempotent (create/index ... if not exists) and safe to re-run, but a
-- FK's ON DELETE behavior can't be altered in place — it has to be
-- dropped and recreated. Safe to run against a fresh database too (the
-- IF EXISTS guards make it a no-op there).
-- ---------------------------------------------------------------------
alter table monitors drop constraint if exists monitors_last_scan_id_fkey;
alter table monitors
  add constraint monitors_last_scan_id_fkey
  foreign key (last_scan_id) references scans(id) on delete set null;
