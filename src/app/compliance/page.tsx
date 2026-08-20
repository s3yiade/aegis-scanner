import TopNav from '@/components/TopNav';
import SiteFooter from '@/components/SiteFooter';

export default function CompliancePage() {
  return (
    <div className="container">
      <TopNav active="/compliance" />

      <div className="eyebrow">
        <span className="dot" />
        In development
      </div>

      <div className="hero">
        <h1>Compliance scanning</h1>
        <p>Coming soon.</p>
      </div>

      <div className="module-grid">
        <div className="module-card">
          <div className="icon">✓</div>
          <h4>Cookie-consent checks</h4>
          <p>Automated verification that consent tooling is present and configured correctly.</p>
        </div>
        <div className="module-card">
          <div className="icon">◫</div>
          <h4>Data-retention signals</h4>
          <p>Surface the kind of retention and handling questions that come up in vendor security reviews.</p>
        </div>
        <div className="module-card">
          <div className="icon">▣</div>
          <h4>SOC 2 / GDPR / PCI readiness</h4>
          <p>A posture check against the questions a real review actually asks — not a certification.</p>
        </div>
      </div>

      <div className="card">
        <p className="muted" style={{ margin: 0 }}>
          Want to be notified when this launches, or need this today? Reach out via the{' '}
          <a href="/consulting" style={{ color: 'var(--accent-bright)' }}>Consulting</a> tab.
        </p>
      </div>

      <SiteFooter />
    </div>
  );
}
