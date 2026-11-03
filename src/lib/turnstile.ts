const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export interface TurnstileResult {
  ok: boolean;
  skipped?: boolean;
  error?: string;
}

function allowedHostnames(env: Env): string[] {
  const configured = String(env.TURNSTILE_HOSTNAMES ?? "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  if (String(env.APP_ENV) !== "production") {
    configured.push("localhost", "127.0.0.1");
  }
  return configured;
}

export function clientIp(request: Request): string {
  return (
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

/** Verify a Turnstile token server-side. Fail closed in production. */
export async function verifyTurnstile(
  env: Env,
  token: string,
  ip: string,
): Promise<TurnstileResult> {
  const secret = env.TURNSTILE_SECRET;
  const production = String(env.APP_ENV) === "production";

  if (!secret) {
    return production
      ? { ok: false, error: "Turnstile is not configured. Add TURNSTILE_SECRET to the Worker." }
      : { ok: true, skipped: true };
  }
  if (!token) return { ok: false, error: "Complete the Turnstile check and try again." };

  try {
    const form = new FormData();
    form.set("secret", secret);
    form.set("response", token);
    if (ip && ip !== "unknown") form.set("remoteip", ip);

    const response = await fetch(SITEVERIFY, {
      method: "POST",
      body: form,
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) return { ok: false, error: "Turnstile verification failed." };

    const data = (await response.json()) as {
      success?: boolean;
      action?: string;
      hostname?: string;
      "error-codes"?: string[];
    };

    if (!data.success) {
      return { ok: false, error: "Turnstile rejected the request. Try again." };
    }
    if (data.action && data.action !== "audit") {
      return { ok: false, error: "Turnstile action did not match." };
    }
    const allowed = allowedHostnames(env);
    if (production && data.hostname && allowed.length && !allowed.includes(data.hostname.toLowerCase())) {
      return { ok: false, error: "Turnstile hostname did not match." };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: "Turnstile verification is unavailable right now." };
  }
}
