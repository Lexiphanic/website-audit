import { env } from "cloudflare:workers";
import { domainFromParam } from "./audit/normalize";
import { getReport, getReportDates, type ReportRow } from "./db";
import { isDateString } from "./util";
import type { ReportPayload } from "./audit/types";

export interface ReportPageData {
  domain: string;
  date: string;
  row: ReportRow | null;
  payload: ReportPayload | null;
  dates: Pick<ReportRow, "report_date" | "score" | "grade" | "status">[];
  error: "invalid-domain" | "invalid-date" | "invalid-report" | null;
}

export async function loadReportPage(rawDomain: string, rawDate = ""): Promise<ReportPageData> {
  const empty = { date: rawDate, row: null, payload: null, dates: [] as ReportPageData["dates"], error: null } as const;
  let domain: string;
  try {
    domain = domainFromParam(rawDomain);
  } catch {
    return { ...empty, domain: rawDomain, error: "invalid-domain" };
  }

  if (rawDate && !isDateString(rawDate)) {
    return { ...empty, domain, error: "invalid-date" };
  }

  const [row, dates] = await Promise.all([
    getReport(env, domain, rawDate || undefined),
    getReportDates(env, domain),
  ]);

  let payload: ReportPayload | null = null;
  if (row?.status === "complete" && row.payload_json) {
    try {
      payload = JSON.parse(row.payload_json) as ReportPayload;
    } catch {
      payload = null;
    }
  }

  if (row?.status === "complete" && !payload) {
    return { domain, date: rawDate, row, payload: null, dates, error: "invalid-report" };
  }

  return { domain, date: rawDate, row, payload, dates, error: null };
}
