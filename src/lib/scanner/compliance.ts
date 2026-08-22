import type { Finding } from '@/types/scan';

/**
 * Maps individual scan findings to the compliance framework controls they
 * bear on. This is explicitly NOT a certified compliance assessment — see
 * COMPLIANCE_DISCLAIMER below, which every surface displaying this mapping
 * (report page, PDF) must show alongside it. What it IS: a way to tell a
 * reader "this specific technical gap is the kind of thing your SOC 2
 * auditor or PCI QSA is going to ask about," which is genuinely useful
 * context a plain pass/fail list doesn't give — but a technical scan can
 * only ever observe a fraction of what any of these frameworks actually
 * require (policies, personnel, physical security, evidence retention,
 * vendor management, and far more live entirely outside what an external
 * HTTP scan can see).
 *
 * Control IDs are real, current identifiers:
 *   - SOC 2: AICPA Trust Services Criteria (2017, as amended)
 *   - PCI-DSS: v4.0 requirement numbering
 *   - ISO 27001: the 2022 Annex A control set
 * Mappings are deliberately conservative — a finding is only mapped to a
 * control where the connection is direct and defensible (e.g. missing TLS
 * -> "encrypt transmission of data," PCI-DSS 4.2.1), not stretched to
 * cover every control a security program might eventually touch.
 */

export type ComplianceFramework = 'soc2' | 'pci_dss' | 'iso27001';

export interface ComplianceControlRef {
  framework: ComplianceFramework;
  controlId: string;
  controlTitle: string;
}

export const FRAMEWORK_META: Record<ComplianceFramework, { label: string; shortLabel: string }> = {
  soc2: { label: 'SOC 2 (AICPA Trust Services Criteria)', shortLabel: 'SOC 2' },
  pci_dss: { label: 'PCI-DSS v4.0', shortLabel: 'PCI-DSS' },
  iso27001: { label: 'ISO/IEC 27001:2022 (Annex A)', shortLabel: 'ISO 27001' },
};

export const COMPLIANCE_DISCLAIMER =
  "This mapping is directional context, not a compliance assessment. It is not a SOC 2 audit, PCI-DSS Report on Compliance, ISO 27001 certification, or any kind of formal attestation or gap assessment — passing every check in this scan does not mean you're compliant with any of these frameworks, and failing one doesn't mean you're not. Each framework has requirements this scan has no way to observe (written policies, personnel and training, physical security, vendor management, evidence retention, and more). Use this to anticipate what an auditor or assessor is likely to flag, then work with one directly for an actual assessment.";

function ref(framework: ComplianceFramework, controlId: string, controlTitle: string): ComplianceControlRef {
  return { framework, controlId, controlTitle };
}

const SOC2_TRANSMISSION = ref('soc2', 'CC6.7', 'Restricts transmission/movement of information to authorized channels');
const SOC2_BOUNDARY = ref('soc2', 'CC6.6', 'Restricts logical access via boundary/perimeter protections');
const SOC2_ACCESS = ref('soc2', 'CC6.1', 'Restricts logical access to authorized users');
const SOC2_MALWARE = ref('soc2', 'CC6.8', 'Prevents/detects unauthorized or malicious software');
const SOC2_DETECTION = ref('soc2', 'CC7.1', 'Detects and evaluates security events/vulnerabilities');
const SOC2_MONITORING = ref('soc2', 'CC7.2', 'Monitors systems for anomalies indicating compromise');
const SOC2_CHANGE_MGMT = ref('soc2', 'CC8.1', 'Change management over infrastructure, data, software, and procedures');

const PCI_TLS = ref('pci_dss', '4.2.1', 'Strong cryptography protects cardholder data during transmission over public networks');
const PCI_SECURE_CONFIG = ref('pci_dss', '2.2.1', 'System components configured securely; insecure services/protocols disabled');
const PCI_PUBLIC_APP_PROTECT = ref('pci_dss', '6.4.1', 'Public-facing web applications protected against common attacks');
const PCI_CUSTOM_SOFTWARE = ref('pci_dss', '6.3.2', 'Bespoke/custom software reviewed for vulnerabilities, including hardcoded credentials');
const PCI_NEED_TO_KNOW = ref('pci_dss', '7.2.1', 'Access to system components restricted based on need-to-know');

const ISO_CRYPTO = ref('iso27001', 'A.8.24', 'Use of cryptography');
const ISO_APP_SECURITY = ref('iso27001', 'A.8.26', 'Application security requirements');
const ISO_CONFIG_MGMT = ref('iso27001', 'A.8.9', 'Configuration management');
const ISO_DATA_LEAKAGE = ref('iso27001', 'A.8.12', 'Data leakage prevention');
const ISO_SOURCE_ACCESS = ref('iso27001', 'A.8.4', 'Access to source code');
const ISO_ACCESS_CONTROL = ref('iso27001', 'A.5.15', 'Access control');
const ISO_MONITORING = ref('iso27001', 'A.8.16', 'Monitoring activities');
const ISO_SUPPLY_CHAIN = ref('iso27001', 'A.5.21', 'Managing information security in the ICT supply chain');
const ISO_NETWORK_SECURITY = ref('iso27001', 'A.8.20', 'Networks security');

/** Keyed by `${finding.category}:${finding.id}` — matches the same key
 * convention used in lib/scanner/diff.ts. */
const FINDING_CONTROL_MAP: Record<string, ComplianceControlRef[]> = {
  'headers:hsts': [SOC2_TRANSMISSION, PCI_TLS, ISO_CRYPTO],
  'headers:no-https': [SOC2_TRANSMISSION, PCI_TLS, ISO_CRYPTO],
  'headers:https-downgrade': [SOC2_TRANSMISSION, PCI_TLS, ISO_CRYPTO],
  'headers:x-frame-options': [SOC2_BOUNDARY, PCI_PUBLIC_APP_PROTECT, ISO_APP_SECURITY],
  'headers:content-type-options': [SOC2_BOUNDARY, PCI_PUBLIC_APP_PROTECT, ISO_APP_SECURITY],
  'headers:csp': [SOC2_BOUNDARY, PCI_PUBLIC_APP_PROTECT, ISO_APP_SECURITY],
  'headers:referrer-policy': [SOC2_TRANSMISSION, ISO_DATA_LEAKAGE],
  'headers:info-leak': [SOC2_DETECTION, PCI_SECURE_CONFIG, ISO_CONFIG_MGMT],
  'headers:cookie-flags': [SOC2_ACCESS, SOC2_TRANSMISSION, PCI_PUBLIC_APP_PROTECT, ISO_ACCESS_CONTROL],

  'tls:tls-validity': [SOC2_TRANSMISSION, PCI_TLS, ISO_CRYPTO],
  'tls:tls-hostname-match': [SOC2_TRANSMISSION, PCI_TLS, ISO_CRYPTO],
  'tls:tls-expiry': [SOC2_TRANSMISSION, PCI_TLS, ISO_CRYPTO],
  'tls:tls-protocol': [SOC2_TRANSMISSION, PCI_SECURE_CONFIG, ISO_CRYPTO],
  'tls:tls-weak-protocol': [SOC2_TRANSMISSION, PCI_SECURE_CONFIG, ISO_CRYPTO],

  'dns:spf': [SOC2_BOUNDARY, ISO_NETWORK_SECURITY],
  'dns:spf-permissive': [SOC2_BOUNDARY, ISO_NETWORK_SECURITY],
  'dns:dmarc': [SOC2_BOUNDARY, ISO_NETWORK_SECURITY],

  'dns:subdomain-takeover': [SOC2_ACCESS, SOC2_DETECTION, PCI_PUBLIC_APP_PROTECT, ISO_NETWORK_SECURITY],

  'webapp:cors': [SOC2_ACCESS, SOC2_BOUNDARY, PCI_PUBLIC_APP_PROTECT, ISO_APP_SECURITY],
  'webapp:graphql-introspection': [SOC2_ACCESS, PCI_PUBLIC_APP_PROTECT, ISO_APP_SECURITY],
  'webapp:api-docs-exposed': [SOC2_ACCESS, ISO_DATA_LEAKAGE],
  'webapp:client-secrets': [SOC2_ACCESS, SOC2_MALWARE, PCI_CUSTOM_SOFTWARE, ISO_DATA_LEAKAGE, ISO_CRYPTO],
  'webapp:google-firebase-key': [SOC2_ACCESS, PCI_CUSTOM_SOFTWARE, ISO_DATA_LEAKAGE, ISO_CRYPTO],
  'webapp:google-api-key': [SOC2_ACCESS, PCI_CUSTOM_SOFTWARE, ISO_DATA_LEAKAGE, ISO_CRYPTO],
  'webapp:source-maps': [SOC2_ACCESS, PCI_CUSTOM_SOFTWARE, ISO_SOURCE_ACCESS],
  'webapp:sri': [SOC2_MALWARE, ISO_SUPPLY_CHAIN],
  'webapp:vulnerable-js-libraries': [SOC2_MALWARE, PCI_CUSTOM_SOFTWARE, ISO_SUPPLY_CHAIN],
  'webapp:mixed-content': [SOC2_TRANSMISSION, PCI_TLS, ISO_CRYPTO],

  'headers:csp-quality': [SOC2_BOUNDARY, PCI_PUBLIC_APP_PROTECT, ISO_APP_SECURITY],
  'recon:http-methods': [SOC2_BOUNDARY, PCI_SECURE_CONFIG, ISO_CONFIG_MGMT],
  'recon:verbose-errors': [SOC2_DETECTION, PCI_CUSTOM_SOFTWARE, ISO_CONFIG_MGMT],
  'recon:host-header-trust': [SOC2_ACCESS, PCI_PUBLIC_APP_PROTECT, ISO_APP_SECURITY],
  'recon:open-redirect': [SOC2_ACCESS, PCI_PUBLIC_APP_PROTECT, ISO_APP_SECURITY],
  'recon:endpoint-access-surface': [SOC2_ACCESS, PCI_NEED_TO_KNOW, PCI_PUBLIC_APP_PROTECT, ISO_ACCESS_CONTROL],
  'recon:rate-limit-heuristic': [SOC2_MONITORING, ISO_MONITORING],
};

/** Applied to any `cicd:*` finding not explicitly listed below — every
 * CI/CD exposure is fundamentally an access-control/change-management gap
 * regardless of which system's config leaked. */
const CICD_BASE: ComplianceControlRef[] = [SOC2_ACCESS, SOC2_CHANGE_MGMT, PCI_CUSTOM_SOFTWARE, ISO_SOURCE_ACCESS, ISO_CONFIG_MGMT];
/** Additional controls for the CI/CD checks specifically about exposed
 * credential material (vs. just exposed pipeline config). */
const CICD_CREDENTIAL_IDS = new Set(['cicd:package-manager-auth', 'cicd:terraform-state', 'cicd:aws-credentials-file', 'cicd:k8s-secrets-manifest']);

/** Fallback for the `exposure` category's dynamically-generated finding ids
 * (`exposed:${path}` — see exposedPaths.ts) — mapped at the category level
 * since the specific path checked doesn't change which controls apply. */
const EXPOSURE_FALLBACK: ComplianceControlRef[] = [SOC2_ACCESS, PCI_CUSTOM_SOFTWARE, ISO_DATA_LEAKAGE, ISO_SOURCE_ACCESS];

export function getComplianceControls(finding: Finding): ComplianceControlRef[] {
  const key = `${finding.category}:${finding.id}`;
  const direct = FINDING_CONTROL_MAP[key];
  if (direct) return direct;

  if (finding.category === 'cicd') {
    return CICD_CREDENTIAL_IDS.has(key) ? [...CICD_BASE, ISO_CRYPTO] : CICD_BASE;
  }
  if (finding.category === 'exposure') {
    return EXPOSURE_FALLBACK;
  }
  return [];
}

export interface ComplianceControlSummary {
  framework: ComplianceFramework;
  controlId: string;
  controlTitle: string;
  status: 'gap' | 'clear';
  relatedFindingTitles: string[];
}

/** One list per framework, gaps sorted first. Only includes controls this
 * scan actually touched (a finding mapped to it, pass or fail) — not the
 * full control catalog for each framework, since most of any framework's
 * controls are outside what an external scan can observe at all. */
export function summarizeCompliance(findings: Finding[]): Record<ComplianceFramework, ComplianceControlSummary[]> {
  const acc = new Map<string, ComplianceControlSummary>();

  for (const finding of findings) {
    for (const control of getComplianceControls(finding)) {
      const key = `${control.framework}:${control.controlId}`;
      let entry = acc.get(key);
      if (!entry) {
        entry = { framework: control.framework, controlId: control.controlId, controlTitle: control.controlTitle, status: 'clear', relatedFindingTitles: [] };
        acc.set(key, entry);
      }
      if (!finding.passed) {
        entry.status = 'gap';
        if (!entry.relatedFindingTitles.includes(finding.title)) entry.relatedFindingTitles.push(finding.title);
      }
    }
  }

  const result: Record<ComplianceFramework, ComplianceControlSummary[]> = { soc2: [], pci_dss: [], iso27001: [] };
  for (const entry of acc.values()) {
    result[entry.framework].push(entry);
  }
  for (const fw of Object.keys(result) as ComplianceFramework[]) {
    result[fw].sort((a, b) => {
      if (a.status !== b.status) return a.status === 'gap' ? -1 : 1;
      return a.controlId.localeCompare(b.controlId);
    });
  }
  return result;
}
