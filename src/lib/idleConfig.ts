/**
 * Shared idle-clear timeout used by every form that can have sensitive
 * data on screen (scan URLs, emails, unlocked report findings, fix
 * procedures) — see hooks/useIdleTimeout.ts. Centralized so the whole
 * platform clears on the same cadence instead of each page picking its
 * own number.
 *
 * 3 minutes: short enough to matter for a shared/unattended screen,
 * long enough not to wipe out mid-task typing on a normal pause.
 * Nothing in the database is touched by this — it only clears what's
 * currently rendered/typed in the browser.
 */
export const IDLE_TIMEOUT_MS = 3 * 60 * 1000;
