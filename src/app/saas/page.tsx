import TopNav from '@/components/TopNav';
import ScanForm from '@/components/ScanForm';
import SiteFooter from '@/components/SiteFooter';

export default function SaasScansPage() {
  return (
    <div className="container">
      <TopNav active="/saas" />

      <div className="scan-readout" aria-hidden="true">
        <div className="line"><span className="name">CORS policy</span><span className="ok">PASS</span></div>
        <div className="line"><span className="name">GraphQL introspection</span><span className="ok">PASS</span></div>
        <div className="line"><span className="name">Client-side secrets</span><span className="warn">REVIEW</span></div>
        <div className="line"><span className="name">Source maps exposed</span><span className="ok">PASS</span></div>
      </div>

      <ScanForm
        defaultTargetType="api"
        heading="Security scan built for SaaS and web apps"
        subheading="Everything in the standard scan, plus CORS misconfiguration, GraphQL introspection, exposed API docs, client-side secrets, source maps, and supply-chain (SRI) checks."
        storageKeyPrefix="aegis-saas"
      />

      <div className="stat-strip">
        <div className="stat-item">
          <span className="num">CORS</span>
          <span className="label">+ credentials check</span>
        </div>
        <div className="stat-item">
          <span className="num">GraphQL</span>
          <span className="label">introspection probe</span>
        </div>
        <div className="stat-item">
          <span className="num">5 files</span>
          <span className="label">scanned for secrets</span>
        </div>
        <div className="stat-item">
          <span className="num">SRI</span>
          <span className="label">supply-chain check</span>
        </div>
      </div>

      <div className="module-grid">
        <div className="module-card">
          <div className="icon">◈</div>
          <h4>CORS &amp; credentials</h4>
          <p>Flags a wildcard or reflected origin combined with credentialed requests — the combination that lets any site act as a logged-in user.</p>
        </div>
        <div className="module-card">
          <div className="icon">⌁</div>
          <h4>GraphQL &amp; API docs</h4>
          <p>Checks common paths for a publicly queryable schema or exposed Swagger/OpenAPI documentation.</p>
        </div>
        <div className="module-card">
          <div className="icon">◎</div>
          <h4>Client-side secrets</h4>
          <p>Pattern-matches same-origin scripts for AWS, Stripe, Google, and Slack keys — never stores the match itself, only where it was found.</p>
        </div>
        <div className="module-card">
          <div className="icon">▤</div>
          <h4>Source maps &amp; SRI</h4>
          <p>Flags exposed <code>.map</code> files and third-party scripts loaded without an integrity attribute.</p>
        </div>
      </div>

      <SiteFooter />
    </div>
  );
}
