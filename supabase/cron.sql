-- Run this AFTER schema.sql, once per project. Makes Supabase (pg_cron +
-- pg_net) the primary trigger for the re-scan/monitoring job; vercel.json's
-- cron entry stays configured as a same-endpoint fallback in case pg_cron
-- has an outage or the Supabase project is paused. Both call
-- /api/cron/rescan, which is safe to trigger from two sources — see the
-- is_processing claim-lock on the monitors table and the atomic
-- UPDATE...RETURNING claim in api/cron/rescan/route.ts.

create extension if not exists pg_cron;
create extension if not exists pg_net;

-- Secrets go in Supabase Vault rather than inline in the cron job body —
-- pg_cron.job is readable by project admins, so this avoids putting
-- CRON_SECRET in plain text in a table your whole team (or any future
-- collaborator with DB access) can query.
select vault.create_secret('REPLACE_WITH_YOUR_CRON_SECRET', 'aegis_cron_secret');
select vault.create_secret('https://REPLACE_WITH_YOUR_APP_URL', 'aegis_app_url');

-- To rotate either value later:
--   select vault.update_secret(
--     (select id from vault.secrets where name = 'aegis_cron_secret'),
--     'NEW_VALUE'
--   );

select cron.schedule(
  'aegis-rescan-hourly',
  '0 * * * *',
  $$
  select net.http_post(
    url := (select decrypted_secret from vault.decrypted_secrets where name = 'aegis_app_url') || '/api/cron/rescan',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets where name = 'aegis_cron_secret')
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 300000  -- matches maxDuration on api/cron/rescan/route.ts
  );
  $$
);

-- Dormant-domain watch — checks whether any registered-but-dormant
-- lookalike domain has gone live and, if so, scores it against the
-- target. Runs less often than the rescan job since each check can
-- involve several paid-API calls (rendering/similarity) — every 6 hours
-- is enough granularity for "did a threat actor just activate their
-- clone," without running the more expensive analysis unnecessarily often.
select cron.schedule(
  'aegis-clone-watch',
  '0 */6 * * *',
  $$
  select net.http_post(
    url := (select decrypted_secret from vault.decrypted_secrets where name = 'aegis_app_url') || '/api/cron/clone-watch',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets where name = 'aegis_cron_secret')
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 120000
  );
  $$
);

-- Useful maintenance queries:
--   select * from cron.job;                                  -- list schedules
--   select * from cron.job_run_details order by start_time desc limit 20;  -- run history
--   select cron.unschedule('aegis-rescan-hourly');            -- remove the schedule
--   select cron.unschedule('aegis-clone-watch');               -- remove the watch schedule
