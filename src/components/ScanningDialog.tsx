'use client';

import { useEffect, useState } from 'react';
import { SCAN_STATUS_MESSAGES } from '@/lib/scanStatusMessages';

const STEP_INTERVAL_MS = 1300;

/**
 * Replaces the old "the button says Scanning… and the page just sits
 * there" experience. A scan can take up to ~40s (headers/TLS/DNS/exposed
 * paths/webapp/recon checks + the clone-domain sweep, see
 * lib/scanner/index.ts), which is long enough that a static spinner reads
 * as frozen. This cycles through what's actually happening instead.
 */
export default function ScanningDialog() {
  const [stepIndex, setStepIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setStepIndex((i) => (i + 1) % SCAN_STATUS_MESSAGES.length);
    }, STEP_INTERVAL_MS);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Scan in progress">
      <div className="modal-content">
        <div className="scanning-dialog-icon" aria-hidden="true" />
        <h3 style={{ marginTop: 0, textAlign: 'center' }}>Running scan…</h3>
        <p className="scanning-dialog-status" role="status" aria-live="polite">
          {SCAN_STATUS_MESSAGES[stepIndex]}
        </p>
        <div className="scanning-dialog-progress" aria-hidden="true" />
        <p className="muted scanning-dialog-note" style={{ fontSize: '0.82rem' }}>
          Usually done in under a minute — passive, read-only checks only.
        </p>
      </div>
    </div>
  );
}
