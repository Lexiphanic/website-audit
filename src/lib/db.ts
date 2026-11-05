import { nowIso } from "./util";

export interface ReportRow {
  domain: string;
  report_date: string;
  url: string;
  status: "queued" | "running" | "complete" | "failed";
  phase: string;
  progress: number;
  score: number | null;
  grade: string | null;
  payload_json: string | null;
  workflow_id: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}

export async function getReport(env: Env, domain: string): Promise<ReportRow | null> {
  return env.DB.prepare("SELECT * FROM reports WHERE domain = ?1 LIMIT 1")
    .bind(domain)
    .first<ReportRow>();
}

/** A completed or failed scan blocks the domain for this long. */
export const SCAN_COOLDOWN_MS = 10 * 60_000;

/** A queued or running scan older than this is treated as stale. */
export const STALE_SCAN_MS = 30 * 60_000;

/**
 * Atomically claim the right to start a scan for a domain.
 *
 * The upsert only fires when the existing row is old enough, so two requests
 * cannot both claim the same domain. A returning row means this request won.
 */
export async function claimReport(
  env: Env,
  input: { domain: string; date: string; url: string },
): Promise<{ claimed: boolean; row: ReportRow | null }> {
  const now = nowIso();
  const freshBefore = new Date(Date.now() - SCAN_COOLDOWN_MS).toISOString();
  const staleBefore = new Date(Date.now() - STALE_SCAN_MS).toISOString();
  const claimedRow = await env.DB.prepare(
    `INSERT INTO reports (domain, report_date, url, status, phase, progress, created_at, updated_at)
     VALUES (?1, ?2, ?3, 'queued', 'queued', 0, ?4, ?4)
     ON CONFLICT(domain) DO UPDATE SET
       report_date = excluded.report_date,
       url = excluded.url,
       status = 'queued',
       phase = 'queued',
       progress = 0,
       score = NULL,
       grade = NULL,
       payload_json = NULL,
       workflow_id = NULL,
       error = NULL,
       created_at = excluded.created_at,
       updated_at = excluded.updated_at
     WHERE
       (reports.status IN ('queued', 'running') AND reports.created_at <= ?5)
       OR (reports.status NOT IN ('queued', 'running') AND reports.updated_at <= ?6)
     RETURNING *`,
  )
    .bind(input.domain, input.date, input.url, now, staleBefore, freshBefore)
    .first<ReportRow>();

  if (claimedRow) return { claimed: true, row: claimedRow };
  return { claimed: false, row: await getReport(env, input.domain) };
}

export async function setWorkflowId(env: Env, domain: string, workflowId: string): Promise<void> {
  await env.DB.prepare("UPDATE reports SET workflow_id = ?1, updated_at = ?2 WHERE domain = ?3")
    .bind(workflowId, nowIso(), domain)
    .run();
}

export async function updateProgress(
  env: Env,
  domain: string,
  phase: string,
  progress: number,
): Promise<void> {
  await env.DB.prepare(
    "UPDATE reports SET status = 'running', phase = ?1, progress = ?2, updated_at = ?3 WHERE domain = ?4 AND status != 'complete'",
  )
    .bind(phase, progress, nowIso(), domain)
    .run();
}

export async function completeReport(
  env: Env,
  domain: string,
  payloadJson: string,
  score: number | null,
  grade: string,
): Promise<void> {
  await env.DB.prepare(
    `UPDATE reports SET
       status = 'complete', phase = 'complete', progress = 100,
       payload_json = ?1, score = ?2, grade = ?3, error = NULL, updated_at = ?4
     WHERE domain = ?5`,
  )
    .bind(payloadJson, score, grade, nowIso(), domain)
    .run();
}

export async function failReport(env: Env, domain: string, message: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE reports SET status = 'failed', phase = 'failed', progress = 100, error = ?1, updated_at = ?2 WHERE domain = ?3",
  )
    .bind(message.slice(0, 1000), nowIso(), domain)
    .run();
}
