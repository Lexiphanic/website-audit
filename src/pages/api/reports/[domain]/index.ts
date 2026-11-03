import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { domainFromParam } from "../../../../lib/audit/normalize";
import { getReport } from "../../../../lib/db";

export const prerender = false;

/** The stored report as JSON. Useful for debugging and for the print view. */
export const GET: APIRoute = async ({ params }) => {
  const headers = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
  try {
    const domain = domainFromParam(params.domain ?? "");
    const row = await getReport(env, domain);
    if (!row) {
      return new Response(JSON.stringify({ error: "No report for that domain" }), { status: 404, headers });
    }
    if (row.status !== "complete" || !row.payload_json) {
      return new Response(
        JSON.stringify({ status: row.status, phase: row.phase, progress: row.progress }),
        { status: 202, headers },
      );
    }
    return new Response(row.payload_json, { status: 200, headers });
  } catch {
    return new Response(JSON.stringify({ error: "Invalid request" }), { status: 400, headers });
  }
};
