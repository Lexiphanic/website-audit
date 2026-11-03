import { assertSafeUrl } from "./ssrf";
import { sha256 } from "../util";
import type { RedirectHop, RedirectProbe } from "./types";

export const USER_AGENT =
  "Mozilla/5.0 (compatible; LexiphanicAudit/1.0; +https://audit.lexiphanic.co.uk/)";

export interface FetchOptions {
  method?: "GET" | "HEAD";
  timeoutMs?: number;
  maxBytes?: number;
  headers?: Record<string, string>;
  hashBody?: boolean;
}

export interface FetchResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  bytes: number;
  ttfbMs: number;
  contentType: string;
  error?: string;
}

function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value;
  });
  return result;
}

async function readCapped(
  response: Response,
  maxBytes: number,
): Promise<{ body: string; bytes: number }> {
  if (!response.body || maxBytes <= 0) return { body: "", bytes: 0 };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    while (received < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const remaining = maxBytes - received;
      const chunk = value.byteLength > remaining ? value.slice(0, remaining) : value;
      chunks.push(chunk);
      received += chunk.byteLength;
      if (chunk.byteLength < value.byteLength) break;
    }
  } finally {
    if (received >= maxBytes) {
      await reader.cancel().catch(() => undefined);
    }
  }
  const merged = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { body: new TextDecoder("utf-8", { fatal: false }).decode(merged), bytes: received };
}

/**
 * Fetch one URL with SSRF checks, a hard timeout and a capped body. Redirects
 * are never followed implicitly: the caller sees each hop and validates it.
 */
export async function fetchText(url: string, options: FetchOptions = {}): Promise<FetchResult> {
  const { method = "GET", timeoutMs = 8000, maxBytes = 512_000 } = options;
  await assertSafeUrl(url);

  const started = performance.now();
  const response = await fetch(url, {
    method,
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      "user-agent": USER_AGENT,
      accept: "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
      "accept-language": "en-GB,en;q=0.9",
      ...options.headers,
    },
  });

  const ttfbMs = Math.round(performance.now() - started);
  const headers = headersToObject(response.headers);
  const setCookies =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [headers["set-cookie"] ?? ""].filter(Boolean);

  let body = "";
  let bytes = 0;
  if (method !== "HEAD" && response.status !== 204 && response.status !== 304) {
    const read = await readCapped(response, maxBytes);
    body = read.body;
    bytes = read.bytes;
  }

  return {
    url,
    status: response.status,
    headers,
    setCookies,
    body,
    bytes,
    ttfbMs,
    contentType: headers["content-type"] ?? "",
  };
}

/** Follow a redirect chain manually, validating every target. */
export async function followRedirects(
  startUrl: string,
  options: { maxHops?: number; hashBody?: boolean } = {},
): Promise<RedirectProbe> {
  const maxHops = options.maxHops ?? 10;
  const hops: RedirectHop[] = [];
  let current = startUrl;
  let status = 0;
  let location = "";
  let bodyHash: string | undefined;
  let error: string | undefined;
  let firstHeaders: Record<string, string> = {};
  let finalHeaders: Record<string, string> = {};

  try {
    for (let index = 0; index < maxHops; index += 1) {
      let result = await fetchText(current, {
        method: "HEAD",
        timeoutMs: 7000,
        maxBytes: 0,
      });

      // Some origins reject HEAD. Fall back to GET once.
      if (result.status === 405 || result.status === 501 || result.status === 403) {
        result = await fetchText(current, {
          method: "GET",
          timeoutMs: 8000,
          maxBytes: options.hashBody ? 256_000 : 0,
        });
      }

      if (index === 0) firstHeaders = result.headers;
      finalHeaders = result.headers;
      status = result.status;
      location = result.headers.location ?? "";
      hops.push({ url: current, status, location, ms: result.ttfbMs });

      if (status >= 300 && status < 400 && location) {
        const next = new URL(location, current).href;
        current = next;
        continue;
      }

      if (options.hashBody && status >= 200 && status < 300) {
        const bodyResult = result.body
          ? result
          : await fetchText(current, { timeoutMs: 8000, maxBytes: 256_000 });
        if (bodyResult.body) bodyHash = await sha256(bodyResult.body);
      }
      break;
    }

    if (hops.length >= maxHops) {
      error = `Redirect chain exceeded ${maxHops} hops`;
    }
  } catch (caught) {
    error = caught instanceof Error ? caught.message : String(caught);
  }

  return {
    url: startUrl,
    status,
    location,
    finalUrl: current,
    hops,
    headers: finalHeaders,
    firstHeaders,
    error,
    bodyHash,
  };
}

export async function fetchJson<T>(
  url: string,
  options: { timeoutMs?: number; headers?: Record<string, string> } = {},
): Promise<T> {
  await assertSafeUrl(url);
  const response = await fetch(url, {
    signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
    headers: {
      "user-agent": USER_AGENT,
      accept: "application/json",
      ...options.headers,
    },
  });
  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  return (await response.json()) as T;
}

/** Fetch a document, following up to three redirects with SSRF checks. */
export async function fetchFollowing(
  url: string,
  options: FetchOptions = {},
): Promise<FetchResult> {
  let current = url;
  let result = await fetchText(current, options);
  for (let hop = 0; hop < 3; hop += 1) {
    if (!(result.status >= 300 && result.status < 400) || !result.headers.location) break;
    current = new URL(result.headers.location, current).href;
    result = await fetchText(current, options);
  }
  return result;
}

/**
 * Status-only probe. HEAD first, then GET when an origin refuses HEAD. This
 * avoids a false "broken" result from a WAF that only allows GET.
 */
export async function probeStatus(url: string, timeoutMs = 6000): Promise<number> {
  const head = await fetchFollowing(url, { method: "HEAD", timeoutMs, maxBytes: 0 });
  if (head.status === 403 || head.status === 405 || head.status === 501) {
    const get = await fetchFollowing(url, { method: "GET", timeoutMs, maxBytes: 0 });
    return get.status;
  }
  return head.status;
}
