import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { nowIso } from "../lib/util";

export const prerender = false;

export const GET: APIRoute = async () => {
  const headers = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
  try {
    await env.DB.prepare("SELECT 1 AS ok").first();
    return new Response(
      JSON.stringify({ status: "ok", service: "lexiphanic-audit", time: nowIso() }),
      { status: 200, headers },
    );
  } catch (error) {
    return new Response(
      JSON.stringify({
        status: "error",
        service: "lexiphanic-audit",
        time: nowIso(),
        error: error instanceof Error ? error.message : String(error),
      }),
      { status: 503, headers },
    );
  }
};
