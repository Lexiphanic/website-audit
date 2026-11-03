import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { domainFromParam, reportPath } from "../../../../lib/audit/normalize";
import { getReport } from "../../../../lib/db";

export const prerender = false;

export const GET: APIRoute = async ({ params }) => {
  const headers = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
  try {
    const domain = domainFromParam(params.domain ?? "");
    const row = await getReport(env, domain);
    if (!row) {
      return new Response(JSON.stringify({ error: "No report for that domain" }), { status: 404, headers });
    }
    return new Response(
      JSON.stringify({
        domain: row.domain,
        date: row.report_date,
        status: row.status,
        phase: row.phase,
        progress: row.progress,
        score: row.score,
        grade: row.grade,
        error: row.error,
        updatedAt: row.updated_at,
        reportUrl: reportPath(row.domain),
      }),
      { status: 200, headers },
    );
  } catch {
    return new Response(JSON.stringify({ error: "Invalid request" }), { status: 400, headers });
  }
};
