import TopNav from '@/components/TopNav';
import ScanForm from '@/components/ScanForm';
import SiteFooter from '@/components/SiteFooter';
import { listNiches } from '@/lib/scanner/niche';

export default function SaasScansPage() {
  return (
    <div className="container">
      <TopNav active="/saas" />

      <div className="scan-readout" aria-hidden="true">
        <div className="line"><span className="name">CORS policy</span><span className="ok">PASS</span></div>
        <div className="line"><span className="name">GraphQL introspection</span><span className="ok">PASS</span></div>
        <div className="line"><span className="name">Endpoint access control</span><span className="warn">REVIEW</span></div>
        <div className="line"><span className="name">Open redirect</span><span className="ok">PASS</span></div>
      </div>

      <ScanForm
        defaultTargetType="api"
        heading="Security scan built for SaaS and web apps"
        subheading="Everything in the standard scan, plus CORS, GraphQL introspection, exposed API docs, client-side secrets, source maps, and attack-surface recon — HTTP method enumeration, verbose error disclosure, Host header trust, open redirects, and unauthenticated endpoint exposure, tailored to the endpoint type you're scanning."
        storageKeyPrefix="aegis-saas"
        niches={listNiches('saas')}
        nichesLabel="SaaS category"
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
          <span className="num">6</span>
          <span className="label">attack-surface recon checks</span>
        </div>
        <div className="stat-item">
          <span className="num">6</span>
          <span className="label">endpoint types supported</span>
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
        <div className="module-card">
          <div className="icon">⌖</div>
          <h4>Endpoint access surface</h4>
          <p>Tell us it&apos;s a billing, admin, profile, webhook, internal, or public-data endpoint, and we probe the paths that endpoint type commonly exposes — the same first move a threat actor researching your API would make.</p>
        </div>
        <div className="module-card">
          <div className="icon">↷</div>
          <h4>Recon: methods, errors, redirects</h4>
          <p>HTTP method enumeration (TRACE/PUT/DELETE), verbose stack-trace/debug-page disclosure, Host header trust (X-Forwarded-Host reflection), open redirects, and a rate-limit heuristic.</p>
        </div>
      </div>

      <SiteFooter />
    </div>
  );
}
