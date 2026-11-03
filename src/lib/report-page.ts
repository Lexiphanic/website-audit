import { env } from "cloudflare:workers";
import { domainFromParam } from "./audit/normalize";
import { getReport, type ReportRow } from "./db";
import type { ReportPayload } from "./audit/types";

export interface ReportPageData {
  domain: string;
  row: ReportRow | null;
  payload: ReportPayload | null;
  error: "invalid-domain" | "invalid-report" | null;
}

export async function loadReportPage(rawDomain: string): Promise<ReportPageData> {
  let domain: string;
  try {
    domain = domainFromParam(rawDomain);
  } catch {
    return { domain: rawDomain, row: null, payload: null, error: "invalid-domain" };
  }

  const row = await getReport(env, domain);

  let payload: ReportPayload | null = null;
  if (row?.status === "complete" && row.payload_json) {
    try {
      payload = JSON.parse(row.payload_json) as ReportPayload;
    } catch {
      payload = null;
    }
  }

  if (row?.status === "complete" && !payload) {
    return { domain, row, payload: null, error: "invalid-report" };
  }

  return { domain, row, payload, error: null };
}
