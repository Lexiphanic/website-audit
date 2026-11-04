import { defineMiddleware } from "astro:middleware";

/**
 * Security headers for Worker-rendered responses. `public/_headers` covers
 * static assets served directly by the ASSETS binding; keep the two in step.
 *
 * The strict CSP is production-only: the Vite dev server needs inline scripts
 * and a websocket for HMR.
 */
const CSP_PRODUCTION = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "script-src 'self' https://challenges.cloudflare.com",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' https://challenges.cloudflare.com",
  "frame-src https://challenges.cloudflare.com",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

export const onRequest = defineMiddleware(async (context, next) => {
  const response = await next();
  const headers = response.headers;

  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

  if (import.meta.env.PROD) {
    headers.set("Content-Security-Policy", CSP_PRODUCTION);
  }

  const path = context.url.pathname;
  if (path.startsWith("/reports/")) {
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Robots-Tag", "noindex, nofollow");
  }
  if (path.startsWith("/api/")) {
    headers.set("Cache-Control", "no-store");
  }

  return response;
});
