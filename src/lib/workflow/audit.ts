import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
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

export interface AuditParams {
  domain: string;
  url: string;
  reportDate: string;
}

const EMPTY_DNS: DnsFacts = {
  records: { a: [], aaaa: [], cname: [], ns: [], mx: [], txt: [], caa: [], dnskey: false, ds: false, ad: false, soa: "" },
  email: {
    spf: {
      present: false,
      record: "",
      records: [],
      qualifier: "",
      lookupCount: 0,
      voidLookups: 0,
    },
    dmarc: {
      present: false,
      record: "",
      policy: "",
      subdomainPolicy: "",
      nonExistentPolicy: "",
      testing: false,
      pct: null,
      rua: "",
      ruf: "",
      adkim: "",
      aspf: "",
      fo: "",
      psd: "",
      externalReporting: [],
    },
    dkimSelectors: [],
    dkimKeys: [],
    bimi: false,
    bimiLogo: "",
    bimiAuthority: "",
    mtaSts: false,
    mtaStsId: "",
    tlsRpt: false,
    tlsRptRua: "",
    dane: [],
  },
  rdap: null,
  resolved: false,
};

const STEP_CONFIG = {
  retries: { limit: 2, delay: "3 seconds" as const, backoff: "linear" as const },
  timeout: "120 seconds" as const,
};

/**
 * The audit pipeline. Each phase is a durable Workflow step with its own
 * retries; a phase that still fails returns a fallback so the rest of the
 * report can complete and the affected checks say "not checked".
 *
 * The browser never waits on this class directly: it polls the D1 row.
 */
export class AuditWorkflow extends WorkflowEntrypoint<Env, AuditParams> {
  async run(event: WorkflowEvent<AuditParams>, step: WorkflowStep): Promise<void> {
    const started = Date.now();
    const { domain, url, reportDate } = event.payload;

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

    const progress = async (phase: string, value: number) => {
      try {
        await updateProgress(this.env, domain, phase, value);
      } catch {
        // A status write must never fail the audit.
      }
    };

    const phase = async <T>(
      name: string,
      value: number,
      fallback: (error: unknown) => T,
      run: () => Promise<T>,
    ): Promise<T> => {
      await progress(name, value);
      try {
        return (await step.do(name, STEP_CONFIG, run as never)) as T;
      } catch (error) {
        facts.errors.push({ phase: name, message: asErrorMessage(error) });
        return fallback(error);
      }
    };

    try {
      const dns = await phase("dns", 10, () => EMPTY_DNS, () => collectDns(domain));
      facts.dns = dns;

      const transport = await phase<TransportFacts | null>("transport", 25, () => null, () =>
        collectTransport(domain, dns),
      );
      facts.transport = transport;

      const target = transport?.homepage.finalUrl || `https://${domain}/`;
      const content = await phase<{ html: HtmlFacts; thirdParties: ThirdPartyFacts } | null>(
        "content",
        40,
        () => null,
        async () => {
          const response = await fetchText(target, { timeoutMs: 12_000, maxBytes: 512_000 });
          return collectHtml(response.body, target, response.status, response.headers);
        },
      );
      const html = content?.html ?? null;
      const homepageThirdParties = content?.thirdParties ?? null;
      facts.html = html;

      const files = await phase<FilesFacts | null>("files", 55, () => null, () =>
        collectFiles(target, html, homepageThirdParties),
      );
      facts.files = files;
      if (files) files.thirdParties.dns = detectDnsProvider(dns.records.ns);

      const security = await phase<SecurityFacts | null>("security", 70, () => null, async () => {
        if (!transport) throw new Error("Transport data is unavailable");
        return collectSecurity(transport.homepage.finalUrl, transport, html);
      });
      facts.security = security;

      const performance = await phase<PerformanceFacts | null>("performance", 85, () => null, async () => {
        if (!transport || !html) throw new Error("Page data is unavailable");
        return collectPerformance(domain, transport, html, this.env.PSI_API_KEY);
      });
      facts.performance = performance;

      const migration = await phase<MigrationFacts | null>("migration", 90, () => null, async () => {
        if (!transport || !html || !files || !security) throw new Error("Earlier phases did not complete");
        return collectMigration(dns, transport, html, files, security);
      });
      facts.migration = migration;

      // SSL Labs is the source for protocol versions and the grade. A fresh
      // scan takes minutes (5m56s for lexiphanic.co.uk), so sleeping here only
      // held the report at 92% and still finished pending. The cached answer
      // from `startLabs` is already in transport; a later run picks up the
      // grade once Labs has finished.

      const results = await phase("score", 95, () => allChecks(facts), async () => allChecks(facts));
      const payload = buildReport(facts, results, Date.now() - started);

      await progress("persist", 98);
      await step.do("persist", STEP_CONFIG, async () => {
        await completeReport(
          this.env,
          domain,
          JSON.stringify(payload),
          payload.meta.score,
          payload.meta.grade,
        );
      });
    } catch (error) {
      await failReport(this.env, domain, asErrorMessage(error));
      throw error;
    }
  }
}
