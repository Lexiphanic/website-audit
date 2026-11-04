import { CATEGORIES, type AuditFacts, type CategoryScore, type CheckResult, type ReportPayload } from "./types";
import { CHECK_DEFINITIONS, definitionFor } from "./registry";

const ENGINE_VERSION = "1.1.0";
const MAX_PAYLOAD_BYTES = 88_000;

function gradeFor(score: number | null): string {
  if (score === null) return "—";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  if (score >= 50) return "E";
  return "F";
}

function scoreFor(status: CheckResult["status"]): number | null {
  if (status === "pass") return 1;
  if (status === "warn") return 0.5;
  if (status === "fail") return 0;
  return null;
}

function countStatus(results: CheckResult[], status: CheckResult["status"]): number {
  return results.filter((result) => result.status === status).length;
}

export function scoreChecks(results: CheckResult[]): {
  overall: number | null;
  grade: string;
  categories: CategoryScore[];
  coverage: { checked: number; total: number };
  counts: ReportPayload["meta"]["counts"];
} {
  const byKey = new Map(results.map((result) => [result.key, result]));
  const categories: CategoryScore[] = [];
  let weighted = 0;
  let weightUsed = 0;

  for (const category of CATEGORIES) {
    let earned = 0;
    let possible = 0;
    let passed = 0;
    let warnings = 0;
    let failed = 0;
    let notChecked = 0;

    for (const definition of CHECK_DEFINITIONS.filter(
      (item) => item.category === category.key && item.weight > 0,
    )) {
      const result = byKey.get(definition.key);
      if (!result) {
        notChecked += 1;
        continue;
      }
      const value = scoreFor(result.status);
      if (value === null) {
        notChecked += 1;
        continue;
      }
      earned += definition.weight * value;
      possible += definition.weight;
      if (result.status === "pass") passed += 1;
      if (result.status === "warn") warnings += 1;
      if (result.status === "fail") failed += 1;
    }

    const score = possible > 0 ? Math.round((earned / possible) * 100) : null;
    categories.push({
      key: category.key,
      label: category.label,
      weight: category.weight,
      score,
      passed,
      warnings,
      failed,
      notChecked,
    });

    if (score !== null) {
      weighted += score * category.weight;
      weightUsed += category.weight;
    }
  }

  const overall = weightUsed > 0 ? Math.round(weighted / weightUsed) : null;
  const totalScored = CHECK_DEFINITIONS.filter((item) => item.weight > 0).length;
  const checked = results.filter(
    (result) => definitionFor(result.key).weight > 0 && scoreFor(result.status) !== null,
  ).length;

  return {
    overall,
    grade: gradeFor(overall),
    categories,
    coverage: { checked, total: totalScored },
    counts: {
      pass: countStatus(results, "pass"),
      warn: countStatus(results, "warn"),
      fail: countStatus(results, "fail"),
      info: countStatus(results, "info"),
      skipped: countStatus(results, "skipped"),
      error: countStatus(results, "error"),
    },
  };
}

function headlineFor(score: number | null): string {
  if (score === null) return "The audit completed with limited coverage.";
  if (score >= 90) return "The site is in good shape for a migration.";
  if (score >= 80) return "A solid site with a few things to fix before it moves.";
  if (score >= 70) return "Workable, but the migration will need some cleanup.";
  if (score >= 60) return "Several issues would make this migration risky.";
  return "This site needs remediation before a move.";
}

function trimFacts(facts: AuditFacts): AuditFacts {
  const copy = structuredClone(facts);
  for (const [key, value] of Object.entries(copy.transport?.homepage.headers ?? {})) {
    copy.transport!.homepage.headers[key] = value.slice(0, 500);
  }
  if (copy.html) {
    copy.html.links = copy.html.links.slice(0, 80);
    copy.html.images = copy.html.images.slice(0, 80);
    copy.html.scripts = copy.html.scripts.slice(0, 80);
    copy.html.headings = copy.html.headings.slice(0, 80);
    copy.html.hreflang = copy.html.hreflang.slice(0, 40);
    copy.html.icons = copy.html.icons.slice(0, 20);
  }
  if (copy.files) {
    copy.files.sitemaps.urls = copy.files.sitemaps.urls.slice(0, 500);
    copy.files.sitemaps.sample = copy.files.sitemaps.sample.slice(0, 10);
    copy.files.sitemaps.pages = copy.files.sitemaps.pages.slice(0, 5);
    copy.files.sitemaps.duplicateTitles = copy.files.sitemaps.duplicateTitles.slice(0, 5);
    if (copy.files.manifestDetails) {
      copy.files.manifestDetails.icons = copy.files.manifestDetails.icons.slice(0, 8);
    }
    if (copy.files.appleTouchIcons) {
      copy.files.appleTouchIcons = copy.files.appleTouchIcons.slice(0, 4);
    }
    if (copy.files.thirdParties) {
      copy.files.thirdParties.providers = copy.files.thirdParties.providers
        .slice(0, 20)
        .map((provider) => ({ ...provider, evidence: provider.evidence.slice(0, 3) }));
      copy.files.thirdParties.domains = copy.files.thirdParties.domains.slice(0, 20);
    }
  }
  if (copy.dns) {
    copy.dns.email.spf.records = copy.dns.email.spf.records.slice(0, 3);
    copy.dns.email.dkimKeys = copy.dns.email.dkimKeys
      .slice(0, 6)
      .map((key) => ({ ...key, record: key.record.slice(0, 600) }));
    copy.dns.email.dmarc.externalReporting = copy.dns.email.dmarc.externalReporting.slice(0, 5);
    copy.dns.email.dane = copy.dns.email.dane.slice(0, 5);
  }
  if (copy.transport?.mtaSts) {
    copy.transport.mtaSts.mx = copy.transport.mtaSts.mx.slice(0, 10);
  }
  if (copy.performance) {
    copy.performance.brokenImages = copy.performance.brokenImages.slice(0, 8);
    copy.performance.brokenLinks = copy.performance.brokenLinks.slice(0, 8);
  }
  return copy;
}

/** Build the stored payload, trimming optional evidence until it fits D1. */
export function buildReport(
  facts: AuditFacts,
  results: CheckResult[],
  durationMs: number,
): ReportPayload {
  const score = scoreChecks(results);
  const topFindings = results
    .filter((result) => result.status === "fail" || result.status === "warn")
    .map((result) => ({ result, definition: definitionFor(result.key) }))
    .sort((a, b) => {
      if (a.result.status !== b.result.status) return a.result.status === "fail" ? -1 : 1;
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return severityOrder[a.definition.severity] - severityOrder[b.definition.severity];
    })
    .slice(0, 5)
    .map(({ result, definition }) => ({
      key: result.key,
      label: definition.label,
      severity: definition.severity,
      observed: result.observed,
    }));

  let payload: ReportPayload = {
    version: 1,
    meta: {
      domain: facts.domain,
      url: facts.url,
      reportDate: facts.reportDate,
      generatedAt: new Date().toISOString(),
      engineVersion: ENGINE_VERSION,
      durationMs,
      score: score.overall,
      grade: score.grade,
      coverage: score.coverage,
      counts: score.counts,
    },
    summary: {
      headline: headlineFor(score.overall),
      topFindings,
    },
    categories: score.categories,
    checks: results,
    facts: trimFacts(facts),
  };

  // Keep evidence only while it fits. The report is still complete without it;
  // the summary and observed values are the important part.
  if (JSON.stringify(payload).length > MAX_PAYLOAD_BYTES) {
    payload = {
      ...payload,
      checks: results.map((result) => ({ ...result, evidence: undefined })),
    };
  }
  if (JSON.stringify(payload).length > MAX_PAYLOAD_BYTES) {
    payload = {
      ...payload,
      facts: {
        ...payload.facts,
        html: payload.facts.html
          ? { ...payload.facts.html, links: [], images: [], scripts: [], headings: [] }
          : null,
        files: payload.facts.files
          ? { ...payload.facts.files, sitemaps: { ...payload.facts.files.sitemaps, urls: [], sample: [], pages: [] } }
          : null,
      },
    };
  }

  return payload;
}

export { gradeFor, ENGINE_VERSION };
