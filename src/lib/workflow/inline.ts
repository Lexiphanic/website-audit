import { collectDns } from "../audit/dns";
import { collectTransport } from "../audit/transport";
import { collectHtml } from "../audit/html";
import { fetchText } from "../audit/fetch";
import { collectFiles } from "../audit/files";
import { collectSecurity } from "../audit/security";
import { collectPerformance } from "../audit/performance";
import { collectMigration } from "../audit/migration";
import { allChecks } from "../audit/checks";
import { buildReport } from "../audit/score";
import { detectDnsProvider } from "../audit/third-parties";
import { completeReport, failReport, updateProgress } from "../db";
import { asErrorMessage } from "../util";
import type {
  AuditFacts,
  DnsFacts,
  FilesFacts,
  HtmlFacts,
  MigrationFacts,
  PerformanceFacts,
  SecurityFacts,
  ThirdPartyFacts,
  TransportFacts,
} from "../audit/types";

const EMPTY_DNS: DnsFacts = {
  records: { a: [], aaaa: [], cname: [], ns: [], mx: [], txt: [], caa: [], dnskey: false, ds: false, ad: false, soa: "" },
  email: {
    spfRecords: [],
    spf: { present: false, record: "", qualifier: "", lookupCount: 0, voidLookups: 0 },
    dmarc: { present: false, record: "", policy: "", subdomainPolicy: "", pct: null, rua: "", ruf: "" },
    dkimSelectors: [],
    bimi: false,
    mtaSts: false,
    tlsRpt: false,
  },
  rdap: null,
  resolved: false,
};

export interface InlineAuditParams {
  domain: string;
  url: string;
  reportDate: string;
}

/**
 * Preview-only runner. Worker Previews cannot bind to the production Workflow
 * with a preview D1 database, so the same collectors run inline. It has no
 * retries or sleeps: the preview is for review, not production throughput.
 */
export async function runAuditInline(env: Env, params: InlineAuditParams): Promise<void> {
  const started = Date.now();
  const { domain, url, reportDate } = params;
  const facts: AuditFacts = {
    domain,
    url,
    reportDate,
    startedAt: new Date().toISOString(),
    dns: null,
    transport: null,
    html: null,
    files: null,
    security: null,
    performance: null,
    migration: null,
    errors: [],
  };

  const phase = async <T>(
    name: string,
    value: number,
    run: () => Promise<T>,
    fallback: (error: unknown) => T,
  ): Promise<T> => {
    try {
      await updateProgress(env, domain, name, value);
    } catch {
      // A status write must never stop the audit.
    }
    try {
      return await run();
    } catch (error) {
      facts.errors.push({ phase: name, message: asErrorMessage(error) });
      return fallback(error);
    }
  };

  try {
    const dns = await phase("dns", 10, () => collectDns(domain), () => EMPTY_DNS);
    facts.dns = dns;

    const transport = await phase<TransportFacts | null>("transport", 25, () => collectTransport(domain, dns), () => null);
    facts.transport = transport;

    const target = transport?.homepage.finalUrl || `https://${domain}/`;
    const content = await phase<{ html: HtmlFacts; thirdParties: ThirdPartyFacts } | null>("content", 40, async () => {
      const response = await fetchText(target, { timeoutMs: 12_000, maxBytes: 512_000 });
      return collectHtml(response.body, target, response.status, response.headers);
    }, () => null);
    const html = content?.html ?? null;
    const homepageThirdParties = content?.thirdParties ?? null;
    facts.html = html;

    const files = await phase<FilesFacts | null>("files", 55, () =>
      collectFiles(target, html, homepageThirdParties), () => null);
    facts.files = files;
    if (files) files.thirdParties.dns = detectDnsProvider(dns.records.ns);

    const security = await phase<SecurityFacts | null>("security", 70, async () => {
      if (!transport) throw new Error("Transport data is unavailable");
      return collectSecurity(transport.homepage.finalUrl, transport, html);
    }, () => null);
    facts.security = security;

    const performance = await phase<PerformanceFacts | null>("performance", 85, async () => {
      if (!transport || !html) throw new Error("Page data is unavailable");
      return collectPerformance(domain, transport, html, env.PSI_API_KEY);
    }, () => null);
    facts.performance = performance;

    const migration = await phase<MigrationFacts | null>("migration", 90, async () => {
      if (!transport || !html || !files || !security) throw new Error("Earlier phases did not complete");
      return collectMigration(dns, transport, html, files, security);
    }, () => null);
    facts.migration = migration;

    // Do not sleep waiting for SSL Labs; the cached answer is already in
    // transport and a later run picks up the grade when Labs has finished.

    const results = allChecks(facts);
    const payload = buildReport(facts, results, Date.now() - started);
    await completeReport(env, domain, JSON.stringify(payload), payload.meta.score, payload.meta.grade);
  } catch (error) {
    await failReport(env, domain, asErrorMessage(error)).catch(() => undefined);
  }
}
