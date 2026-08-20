import TopNav from '@/components/TopNav';
import ScanForm from '@/components/ScanForm';
import SiteFooter from '@/components/SiteFooter';

export default function HomePage() {
  return (
    <div className="container">
      <TopNav active="/" />

      <div className="scan-readout" aria-hidden="true">
        <div className="line"><span className="name">HSTS header</span><span className="ok">PASS</span></div>
        <div className="line"><span className="name">TLS certificate</span><span className="ok">PASS</span></div>
        <div className="line"><span className="name">SPF / DMARC</span><span className="warn">WEAK</span></div>
        <div className="line"><span className="name">Exposed .env / .git</span><span className="ok">PASS</span></div>
      </div>

      <ScanForm
        defaultTargetType="web"
        heading="Free security scan for any website or web app"
        subheading="Headers, TLS, DNS mail-spoofing protection, and common exposed files — checked in under a minute."
        storageKeyPrefix="aegis-web"
      />

      <div className="stat-strip">
        <div className="stat-item">
          <span className="num">&lt;60s</span>
          <span className="label">to first result</span>
        </div>
        <div className="stat-item">
          <span className="num">0–100</span>
          <span className="label">score, A–F grade</span>
        </div>
        <div className="stat-item">
          <span className="num">Passive</span>
          <span className="label">read-only checks</span>
        </div>
        <div className="stat-item">
          <span className="num">120+</span>
          <span className="label">clone domains checked</span>
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>How a scan works</h3>
        <div className="steps">
          <div className="step">
            <div className="step-num">1</div>
            <div className="step-body">
              <span className="step-tag">~10 sec</span>
              <h4>Enter the URL</h4>
              <p>Confirm you own or are authorized to scan it — no login required.</p>
            </div>
          </div>
          <div className="step">
            <div className="step-num">2</div>
            <div className="step-body">
              <span className="step-tag">~40 sec</span>
              <h4>We run the checks</h4>
              <p>Headers, TLS, DNS, exposed paths, and a lookalike-domain sweep — all passive.</p>
            </div>
          </div>
          <div className="step">
            <div className="step-num">3</div>
            <div className="step-body">
              <span className="step-tag">instant</span>
              <h4>Get your score, then the full report</h4>
              <p>See your grade immediately; drop your email to unlock every finding and fix.</p>
            </div>
          </div>
        </div>
      </div>

      <SiteFooter />
    </div>
  );
}
