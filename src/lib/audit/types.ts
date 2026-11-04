export type CategoryKey =
  | "transport"
  | "redirects"
  | "metadata"
  | "crawl"
  | "wellknown"
  | "security"
  | "performance"
  | "migration";

export interface CategoryDefinition {
  key: CategoryKey;
  label: string;
  short: string;
  weight: number;
  description: string;
}

export const CATEGORIES: CategoryDefinition[] = [
  {
    key: "transport",
    label: "Transport & TLS",
    short: "Transport",
    weight: 16,
    description:
      "HTTPS, the certificate, protocol versions, HSTS and the encrypted path a visitor actually takes.",
  },
  {
    key: "redirects",
    label: "Hosts & redirects",
    short: "Redirects",
    weight: 10,
    description:
      "Whether www, the apex and http all agree on one canonical address, without chains or duplicate content.",
  },
  {
    key: "metadata",
    label: "Metadata & social",
    short: "Metadata",
    weight: 12,
    description:
      "Titles, descriptions, canonicals, Open Graph, structured data and the signals search engines and social platforms read.",
  },
  {
    key: "crawl",
    label: "Crawl & index",
    short: "Crawl",
    weight: 12,
    description:
      "robots.txt, sitemaps, status codes, AI crawler rules and whether the site can be understood and indexed cleanly.",
  },
  {
    key: "wellknown",
    label: "Well-known & trust",
    short: "Well-known",
    weight: 8,
    description:
      "security.txt, llms.txt, change-password, MTA-STS, app associations and the other machine-readable trust files.",
  },
  {
    key: "security",
    label: "Security & privacy",
    short: "Security",
    weight: 14,
    description:
      "Security headers, CSP, cookie flags, mixed content, email authentication and the domain's own security posture.",
  },
  {
    key: "performance",
    label: "Performance & UX",
    short: "Performance",
    weight: 14,
    description:
      "Server response, page weight, compression, render-blocking assets, caching and — when available — Lighthouse and Core Web Vitals.",
  },
  {
    key: "migration",
    label: "Migration readiness",
    short: "Migration",
    weight: 14,
    description:
      "What the site runs on, how much content there is, and what moving it to Lexiphanic would involve.",
  },
];

export type CheckStatus = "pass" | "warn" | "fail" | "info" | "skipped" | "error";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface CheckDefinition {
  key: string;
  category: CategoryKey;
  label: string;
  severity: Severity;
  /** 0 means informational only and never affects the score. */
  weight: number;
  why: string;
  fix: string;
}

export interface CheckResult {
  key: string;
  status: CheckStatus;
  observed: string;
  evidence?: string;
  source?: string;
}

export interface RedirectHop {
  url: string;
  status: number;
  location: string;
  ms: number;
}

export interface RedirectProbe {
  url: string;
  status: number;
  location: string;
  finalUrl: string;
  hops: RedirectHop[];
  headers: Record<string, string>;
  firstHeaders: Record<string, string>;
  error?: string;
  bodyHash?: string;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  issuerOrganisation: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  sans: string[];
  serial: string;
  fingerprint: string;
  chainLength: number;
  keyAlgorithm: string;
  keySize: number | null;
  authorized: boolean;
  authorizationError: string;
}

export interface TlsVersionProbe {
  supported: boolean | null;
  protocol: string;
  cipher: string;
  error?: string;
}

export interface TlsProbe {
  certificate: CertificateInfo | null;
  protocol: string;
  cipher: string;
  alpn: string;
  versions: Record<string, TlsVersionProbe>;
  grade: string;
  source: string;
  pending: boolean;
  ocspStapling: boolean | null;
  hasSct: boolean | null;
  supportsAead: boolean | null;
  supportsRc4: boolean | null;
  forwardSecrecy: number | null;
  error?: string;
}

export interface HstsInfo {
  present: boolean;
  raw: string;
  maxAge: number | null;
  includeSubDomains: boolean;
  preload: boolean;
}

export interface TransportFacts {
  probes: RedirectProbe[];
  homepage: {
    status: number;
    finalUrl: string;
    ttfbMs: number;
    htmlBytes: number;
    contentEncoding: string;
    headers: Record<string, string>;
    setCookies: string[];
    error?: string;
  };
  tls: {
    apex: TlsProbe | null;
    www: TlsProbe | null;
  };
  hsts: {
    apex: HstsInfo;
    www: HstsInfo;
    preloadStatus: string | null;
  };
  mtaSts: MtaStsPolicyFacts | null;
  ipv6: boolean;
  http2: boolean;
  http3: boolean;
  wwwReachable: boolean;
  pathProbe: RedirectProbe;
  indexProbe: RedirectProbe;
  notFoundProbe: RedirectProbe;
}

export interface DnsRecords {
  a: string[];
  aaaa: string[];
  cname: string[];
  ns: string[];
  mx: { priority: number; host: string }[];
  txt: string[];
  caa: { flags: number; tag: string; value: string }[];
  dnskey: boolean;
  ds: boolean;
  ad: boolean;
  soa: string;
}

export interface SpfFacts {
  present: boolean;
  record: string;
  records: string[];
  qualifier: string;
  lookupCount: number;
  voidLookups: number;
  error?: string;
}

export interface DmarcExternalReportFact {
  target: string;
  authorized: boolean;
  record: string;
}

export interface DmarcFacts {
  present: boolean;
  record: string;
  policy: string;
  subdomainPolicy: string;
  nonExistentPolicy: string;
  testing: boolean;
  pct: number | null;
  rua: string;
  ruf: string;
  adkim: string;
  aspf: string;
  fo: string;
  psd: string;
  externalReporting: DmarcExternalReportFact[];
}

export interface DkimKeyFact {
  selector: string;
  record: string;
  keyType: string;
  bits: number | null;
  revoked: boolean;
  testing: boolean;
  hashAlgorithms: string[];
  error?: string;
}

export interface DaneFact {
  host: string;
  records: string[];
}

export interface EmailAuthFacts {
  spf: SpfFacts;
  dmarc: DmarcFacts;
  dkimSelectors: string[];
  dkimKeys: DkimKeyFact[];
  bimi: boolean;
  bimiLogo: string;
  bimiAuthority: string;
  mtaSts: boolean;
  mtaStsId: string;
  tlsRpt: boolean;
  tlsRptRua: string;
  dane: DaneFact[];
}

export interface MtaStsPolicyFacts {
  present: boolean;
  url: string;
  status: number;
  mode: string;
  maxAge: number;
  mx: string[];
  error?: string;
}

export interface RdapFacts {
  registrar: string;
  registered: string;
  expires: string;
  updated: string;
  statuses: string[];
  nameservers: string[];
  secureDns: boolean;
}

export interface DnsFacts {
  records: DnsRecords;
  email: EmailAuthFacts;
  rdap: RdapFacts | null;
  resolved: boolean;
  error?: string;
}

export interface HtmlImageFact {
  src: string;
  alt: string;
  loading: string;
  width: string;
  height: string;
  format: string;
}

export interface HtmlScriptFact {
  src: string;
  integrity: string;
  async: boolean;
  defer: boolean;
  thirdParty: boolean;
}

export interface HtmlFacts {
  finalUrl: string;
  status: number;
  title: string;
  description: string;
  canonical: string;
  robots: string;
  lang: string;
  charset: string;
  viewport: string;
  themeColor: string;
  og: Record<string, string>;
  twitter: Record<string, string>;
  icons: { rel: string; href: string; sizes: string; type: string }[];
  manifestHref: string;
  jsonLd: { valid: boolean; type: string; error: string }[];
  hreflang: { lang: string; href: string }[];
  headings: { level: number; text: string }[];
  images: HtmlImageFact[];
  scripts: HtmlScriptFact[];
  stylesheets: string[];
  inlineStyleBytes: number;
  forms: { action: string; method: string }[];
  links: { href: string; text: string; internal: boolean }[];
  generator: string;
  platform: string;
  platformConfidence: "high" | "medium" | "low";
  analytics: string[];
  consent: string[];
  social: string[];
  emails: string[];
  phones: string[];
  wordCount: number;
  domSize: number;
  mixedContent: string[];
  hasSkipLink: boolean;
  hasMain: boolean;
  metaCount: number;
  duplicateMeta: number;
  ogImageStatus: number;
  bodyHash: string;
}

export interface FileEntryFact {
  path: string;
  status: number;
  contentType: string;
  bytes: number;
  soft404: boolean;
  error?: string;
}

export interface SitemapPageFact {
  url: string;
  title: string;
  description: string;
  canonical: string;
  robots: string;
  xRobots: string;
}

export type ThirdPartyCategory =
  | "advertising"
  | "analytics"
  | "tag-manager"
  | "session-replay"
  | "consent"
  | "social"
  | "embedded"
  | "functional";

export type PrivacyLevel = "high" | "medium" | "low";

export interface ThirdPartyProviderFact {
  name: string;
  category: ThirdPartyCategory;
  privacy: PrivacyLevel;
  evidence: string[];
  source: "script" | "stylesheet" | "image" | "iframe" | "hint" | "inline";
}

export interface ThirdPartyDomainFact {
  host: string;
  count: number;
  categories: ThirdPartyCategory[];
}

export interface EdgeFact {
  name: string;
  confidence: "high" | "medium" | "low";
  evidence: string[];
}

export interface ThirdPartyFacts {
  edge: EdgeFact | null;
  dns: EdgeFact | null;
  providers: ThirdPartyProviderFact[];
  domains: ThirdPartyDomainFact[];
  consent: string[];
}

export interface IconFact {
  rel: string;
  href: string;
  sizes: string;
  declaredType: string;
  status: number;
  contentType: string;
  bytes: number;
  error?: string;
}

export interface ManifestIconFact {
  src: string;
  sizes: string;
  type: string;
  purpose: string;
}

export interface ManifestFacts {
  present: boolean;
  href: string;
  status: number;
  valid: boolean;
  error?: string;
  name: string;
  shortName: string;
  startUrl: string;
  display: string;
  themeColor: string;
  backgroundColor: string;
  icons: ManifestIconFact[];
  iconSizes: string[];
}

export interface FilesFacts {
  entries: Record<string, FileEntryFact>;
  robots: {
    present: boolean;
    status: number;
    sitemaps: string[];
    blocksAll: boolean;
    blockedPaths: string[];
    aiRules: Record<string, string[] | null>;
  };
  sitemaps: {
    present: boolean;
    valid: boolean;
    urls: string[];
    count: number;
    sample: { url: string; status: number; error?: string }[];
    pages: SitemapPageFact[];
    duplicateTitles: string[];
    lastmod: string;
    source: string;
  };
  securityTxt: {
    present: boolean;
    path: string;
    fields: Record<string, string[]>;
    expired: boolean;
    canonical: string;
    contentType: string;
  };
  llms: {
    root: boolean;
    wellKnown: boolean;
    full: boolean;
    bytes: number;
    headings: number;
    links: number;
  };
  aiTxt: boolean;
  changePassword: boolean;
  aasa: boolean;
  assetlinks: boolean;
  mtaSts: boolean;
  gpc: boolean;
  trustTxt: boolean;
  nodeinfo: boolean;
  webfinger: boolean;
  hostMeta: boolean;
  humansTxt: boolean;
  adsTxt: boolean;
  appAdsTxt: boolean;
  browserconfig: boolean;
  manifest: boolean;
  manifestDetails: ManifestFacts;
  rootIcons: { favicon: boolean; appleTouch: boolean };
  appleTouchIcons: IconFact[];
  maskIcon: IconFact | null;
  thirdParties: ThirdPartyFacts;
}

export interface SecurityFacts {
  headers: Record<string, string>;
  csp: {
    present: boolean;
    reportOnly: boolean;
    directives: Record<string, string[]>;
    unsafeInline: boolean;
    unsafeEval: boolean;
    wildcard: boolean;
    reportUri: boolean;
  };
  cookies: {
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string;
    prefixed: boolean;
  }[];
  xcto: string;
  frameOptions: string;
  referrerPolicy: string;
  permissionsPolicy: string;
  coop: string;
  corp: string;
  sri: { externalScripts: number; withIntegrity: number };
  forms: { action: string; method: string; insecure: boolean }[];
  trackers: string[];
  consent: string[];
  legal: {
    privacy: boolean;
    terms: boolean;
    cookies: boolean;
    accessibility: boolean;
    statuses: Record<string, number>;
  };
  serverDisclosure: { server: string; poweredBy: string };
}

export interface PsiFacts {
  performance: number | null;
  accessibility: number | null;
  bestPractices: number | null;
  seo: number | null;
  lcp: string;
  cls: string;
  inp: string;
  ttfb: string;
  fcp: string;
  tbt: string;
  fieldData: string;
  error?: string;
}

export interface PerformanceFacts {
  ttfbMs: number;
  htmlBytes: number;
  contentEncoding: string;
  renderBlocking: number;
  renderBlockingUrls: string[];
  assetBytes: number;
  assetCount: number;
  imageFormats: Record<string, number>;
  fontDisplay: string;
  thirdPartyDomains: string[];
  domSize: number;
  cacheControl: string;
  cdn: string;
  brokenImages: string[];
  brokenLinks: string[];
  psi: PsiFacts | null;
}

export interface MigrationFacts {
  platform: string;
  platformConfidence: "high" | "medium" | "low";
  hosting: string;
  pageCount: number;
  ecommerce: string[];
  booking: string[];
  analytics: string[];
  emailProvider: string;
  registrar: string;
  domainExpires: string;
  transferLocked: boolean | null;
  dnsSummary: { a: number; aaaa: number; mx: number; ns: number; caa: number; txt: number };
  emails: string[];
  phones: string[];
  social: string[];
  legalPages: string[];
  legacy: string[];
  languages: string[];
  redirectComplexity: number;
  content: { words: number; images: number; pages: number };
}

export interface AuditFacts {
  domain: string;
  url: string;
  reportDate: string;
  startedAt: string;
  dns: DnsFacts | null;
  transport: TransportFacts | null;
  html: HtmlFacts | null;
  files: FilesFacts | null;
  security: SecurityFacts | null;
  performance: PerformanceFacts | null;
  migration: MigrationFacts | null;
  errors: { phase: string; message: string }[];
}

export interface CategoryScore {
  key: CategoryKey;
  label: string;
  weight: number;
  score: number | null;
  passed: number;
  warnings: number;
  failed: number;
  notChecked: number;
}

export interface ReportPayload {
  version: number;
  meta: {
    domain: string;
    url: string;
    reportDate: string;
    generatedAt: string;
    engineVersion: string;
    durationMs: number;
    score: number | null;
    grade: string;
    coverage: { checked: number; total: number };
    counts: { pass: number; warn: number; fail: number; info: number; skipped: number; error: number };
  };
  summary: {
    headline: string;
    topFindings: { key: string; label: string; severity: Severity; observed: string }[];
  };
  categories: CategoryScore[];
  checks: CheckResult[];
  facts: AuditFacts;
}
