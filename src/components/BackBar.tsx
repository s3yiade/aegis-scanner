'use client';

export default function BackBar({ href = '/', label = 'Back to scanner' }: { href?: string; label?: string }) {
  return (
    <div className="back-bar">
      <a href={href} className="back-bar-inner">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M15 6l-6 6 6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        {label}
      </a>
    </div>
  );
}
