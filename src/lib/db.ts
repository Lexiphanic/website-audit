import { nowIso } from "./util";

export interface ReportRow {
  id: string;
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

export async function getReport(
  env: Env,
  domain: string,
  date?: string,
): Promise<ReportRow | null> {
  const query = date
    ? env.DB.prepare(
        "SELECT * FROM reports WHERE domain = ?1 AND report_date = ?2 LIMIT 1",
      ).bind(domain, date)
    : env.DB.prepare(
        "SELECT * FROM reports WHERE domain = ?1 ORDER BY report_date DESC LIMIT 1",
      ).bind(domain);
  return query.first<ReportRow>();
}

export async function getReportDates(
  env: Env,
  domain: string,
  limit = 12,
): Promise<Pick<ReportRow, "report_date" | "score" | "grade" | "status">[]> {
  const result = await env.DB.prepare(
    "SELECT report_date, score, grade, status FROM reports WHERE domain = ?1 ORDER BY report_date DESC LIMIT ?2",
  )
    .bind(domain, limit)
    .all<Pick<ReportRow, "report_date" | "score" | "grade" | "status">>();
  return result.results ?? [];
}

export async function hasFreshReport(
  env: Env,
  domain: string,
  date: string,
  minutes: number,
): Promise<ReportRow | null> {
  const row = await getReport(env, domain, date);
  if (!row) return null;
  const updated = new Date(row.updated_at).valueOf();
  if (row.status === "queued" || row.status === "running") {
    // A stuck run must not block the domain for ever.
    return Date.now() - updated < 15 * 60_000 ? row : null;
  }
  if (row.status === "complete") {
    if (Date.now() - updated < minutes * 60_000) return row;
  }
  return null;
}

export async function queueReport(
  env: Env,
  input: { id: string; domain: string; date: string; url: string },
): Promise<void> {
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO reports (id, domain, report_date, url, status, phase, progress, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, 'queued', 'queued', 0, ?5, ?5)
     ON CONFLICT(domain, report_date) DO UPDATE SET
       url = excluded.url,
       status = 'queued',
       phase = 'queued',
       progress = 0,
       score = NULL,
       grade = NULL,
       payload_json = NULL,
       workflow_id = NULL,
       error = NULL,
       updated_at = excluded.updated_at`,
  )
    .bind(input.id, input.domain, input.date, input.url, now)
    .run();
}

export async function setWorkflowId(env: Env, id: string, workflowId: string): Promise<void> {
  await env.DB.prepare("UPDATE reports SET workflow_id = ?1, updated_at = ?2 WHERE id = ?3")
    .bind(workflowId, nowIso(), id)
    .run();
}

export async function updateProgress(
  env: Env,
  id: string,
  phase: string,
  progress: number,
): Promise<void> {
  await env.DB.prepare(
    "UPDATE reports SET status = 'running', phase = ?1, progress = ?2, updated_at = ?3 WHERE id = ?4 AND status != 'complete'",
  )
    .bind(phase, progress, nowIso(), id)
    .run();
}

export async function completeReport(
  env: Env,
  id: string,
  payloadJson: string,
  score: number | null,
  grade: string,
): Promise<void> {
  await env.DB.prepare(
    `UPDATE reports SET
       status = 'complete', phase = 'complete', progress = 100,
       payload_json = ?1, score = ?2, grade = ?3, error = NULL, updated_at = ?4
     WHERE id = ?5`,
  )
    .bind(payloadJson, score, grade, nowIso(), id)
    .run();
}

export async function failReport(env: Env, id: string, message: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE reports SET status = 'failed', phase = 'failed', progress = 100, error = ?1, updated_at = ?2 WHERE id = ?3",
  )
    .bind(message.slice(0, 1000), nowIso(), id)
    .run();
}
