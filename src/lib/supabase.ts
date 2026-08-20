import { createClient } from '@supabase/supabase-js';

// Service-role client. NEVER import this into a "use client" component or
// expose SUPABASE_SERVICE_ROLE_KEY via NEXT_PUBLIC_*; it bypasses RLS.
// All DB access happens inside API routes / server components only.
export function getSupabaseAdmin() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    throw new Error('Supabase env vars are not configured');
  }
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}
