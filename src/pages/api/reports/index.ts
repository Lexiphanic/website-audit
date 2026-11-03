import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";
import { normalizeTarget, reportPath } from "../../../lib/audit/normalize";
import { hasFreshReport, queueReport, failReport, setWorkflowId } from "../../../lib/db";
import { ukDate } from "../../../lib/util";
import { clientIp, verifyTurnstile } from "../../../lib/turnstile";

export const prerender = false;

interface Submission {
  url: string;
  token: string;
  refresh: boolean;
  wantsJson: boolean;
}

async function readSubmission(request: Request): Promise<Submission> {
  const contentType = request.headers.get("content-type") ?? "";
  const wantsJson =
    contentType.includes("application/json") ||
    (request.headers.get("accept") ?? "").includes("application/json");

  if (contentType.includes("application/json")) {
    const body = (await request.json()) as Record<string, unknown>;
    return {
      url: String(body.url ?? ""),
      token: String(body.turnstileToken ?? body["cf-turnstile-response"] ?? ""),
      refresh: Boolean(body.refresh),
      wantsJson: true,
    };
  }

  const form = await request.formData();
  return {
    url: String(form.get("url") ?? ""),
    token: String(form.get("cf-turnstile-response") ?? ""),
    refresh: form.get("refresh") === "1",
    wantsJson,
  };
}

export const POST: APIRoute = async ({ request, redirect }) => {
  let submission: Submission;
  try {
    submission = await readSubmission(request);
  } catch {
    return Response.json({ error: "Could not read the form." }, { status: 400 });
  }

  const { url, token, refresh, wantsJson } = submission;

  const respond = (message: string, status = 400) => {
    if (wantsJson) return Response.json({ error: message }, { status });
    const params = new URLSearchParams({ error: message });
    if (url) params.set("url", url);
    return redirect(`/?${params.toString()}`, 303);
  };

  const ip = clientIp(request);
  const rate = await env.SCAN_RATE.limit({ key: `${ip}:scan` });
  if (!rate.success) {
    return respond("That was a lot of audits in a short time. Please wait a minute and try again.", 429);
  }

  const turnstile = await verifyTurnstile(env, token, ip);
  if (!turnstile.ok) {
    return respond(turnstile.error ?? "Complete the Turnstile check and try again.", 403);
  }

  let target;
  try {
    target = normalizeTarget(url);
  } catch (error) {
    return respond(error instanceof Error ? error.message : "Enter a valid website address.");
  }

  const reportUrl = reportPath(target.domain);

  try {
    if (!refresh) {
      const existing = await hasFreshReport(env, target.domain, 5);
      if (existing && existing.status !== "failed") {
        return wantsJson
          ? Response.json({ domain: target.domain, reportUrl, status: existing.status }, { status: 202 })
          : redirect(reportUrl, 303);
      }
    }

    const date = ukDate();
    await queueReport(env, {
      domain: target.domain,
      date,
      url: `https://${target.domain}/`,
    });

    const instance = await env.AUDIT_WORKFLOW.create({
      params: {
        domain: target.domain,
        url: `https://${target.domain}/`,
        reportDate: date,
      },
    });
    await setWorkflowId(env, target.domain, instance.id);

    return wantsJson
      ? Response.json({ domain: target.domain, reportUrl }, { status: 202 })
      : redirect(reportUrl, 303);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await failReport(env, target.domain, message).catch(() => undefined);
    return respond(`The audit could not be started: ${message}`, 500);
  }
};
