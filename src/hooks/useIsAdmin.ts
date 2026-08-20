'use client';

import { useEffect, useState } from 'react';

interface AdminSessionState {
  isAdmin: boolean;
  adminEmail: string | null;
  loading: boolean;
}

/**
 * Frontend correlate for the backend's admin bypass logic (see
 * lib/adminAuth.ts's isAdminRequest — used across /api/scan, /api/lead,
 * /api/monitor, /api/consult, /api/clone-watch and the report-page
 * unlock actions to skip captcha/rate-limit/disposable-email checks for
 * an authenticated admin session).
 *
 * Defaults closed (`isAdmin: false`) until the check resolves, so a slow
 * network never accidentally renders the reduced-friction UI for a
 * non-admin visitor — worst case an admin briefly sees the normal form
 * before it swaps, never the other way around.
 */
export function useIsAdmin(): AdminSessionState {
  const [state, setState] = useState<AdminSessionState>({ isAdmin: false, adminEmail: null, loading: true });

  useEffect(() => {
    let cancelled = false;
    fetch('/api/admin/session')
      .then((r) => r.json())
      .then((data) => {
        if (cancelled) return;
        setState({ isAdmin: Boolean(data.isAdmin), adminEmail: data.email ?? null, loading: false });
      })
      .catch(() => {
        if (!cancelled) setState({ isAdmin: false, adminEmail: null, loading: false });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
