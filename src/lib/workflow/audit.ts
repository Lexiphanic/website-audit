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
import { pollLabs, tlsFromLabs } from "../audit/tls";
import { buildReport } from "../audit/score";
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
    spfRecords: [],
    spf: { present: false, record: "", qualifier: "", lookupCount: 0 },
    dmarc: { present: false, record: "", policy: "", subdomainPolicy: "", pct: null, rua: "", ruf: "" },
    dkimSelectors: [],
    bimi: false,
    mtaSts: false,
    tlsRpt: false,
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

      const html = await phase<HtmlFacts | null>("content", 40, () => null, async () => {
        const target = transport?.homepage.finalUrl || `https://${domain}/`;
        const response = await fetchText(target, { timeoutMs: 12_000, maxBytes: 512_000 });
        return collectHtml(response.body, target, response.status, response.headers);
      });
      facts.html = html;

      const files = await phase<FilesFacts | null>("files", 55, () => null, () =>
        collectFiles(transport?.homepage.finalUrl || `https://${domain}/`, html),
      );
      facts.files = files;

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

      // SSL Labs is the source for protocol versions and the grade. A first
      // scan can take a minute, so the report is allowed to complete without
      // it: the certificate from crt.sh is already in hand.
      if (transport?.tls.apex?.pending) {
        await progress("tls-grade", 92);
        let current = transport.tls.apex;
        let tlsHost = domain;
        try {
          tlsHost = new URL(transport.homepage.finalUrl).hostname;
        } catch {
          // keep the apex
        }
        for (let attempt = 0; attempt < 3; attempt += 1) {
          await step.sleep(`tls-wait-${attempt}`, "25 seconds");
          try {
            const summary = await step.do(`tls-poll-${attempt}`, STEP_CONFIG, () => pollLabs(tlsHost));
            current = tlsFromLabs(summary, current.certificate);
            if (summary.http2) transport.http2 = true;
            if (!current.pending) break;
          } catch (error) {
            facts.errors.push({ phase: "tls-grade", message: asErrorMessage(error) });
            break;
          }
        }
        transport.tls.apex = current;
        if (transport.wwwReachable) transport.tls.www = current;
      }

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
