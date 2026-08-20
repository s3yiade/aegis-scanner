'use client';

const TABS = [
  { href: '/', label: 'Web Scans' },
  { href: '/saas', label: 'SaaS Scans' },
  { href: '/compliance', label: 'Compliance' },
  { href: '/consulting', label: 'Consulting' },
  { href: '/my-scans', label: 'My Scans' },
];

function ShieldMark() {
  return (
    <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M12 2.5l7.5 3v5.2c0 4.8-3.15 8.86-7.5 10.3-4.35-1.44-7.5-5.5-7.5-10.3V5.5l7.5-3z"
        fill="white"
        fillOpacity="0.92"
      />
      <path d="M9 12.2l2.1 2.1L15.4 10" stroke="#ea580c" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function TopNav({ active }: { active: string }) {
  return (
    <header className="site-header">
      <div className="site-header-inner">
        <div className="brand-row">
          <a href="/" className="brand">
            <span className="brand-mark">
              <ShieldMark />
            </span>
            Aegis
          </a>
          <span className="env-tag">free scan</span>
        </div>
        <nav className="top-nav" aria-label="Main">
          {TABS.map((tab) => (
            <a key={tab.href} href={tab.href} className={`top-nav-tab${tab.href === active ? ' active' : ''}`}>
              {tab.label}
            </a>
          ))}
        </nav>
      </div>
    </header>
  );
}
