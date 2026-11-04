import { probeStatus } from "./fetch";
import type {
  HtmlFacts,
  SecurityFacts,
  TransportFacts,
} from "./types";

function parseCsp(raw: string, reportOnly: boolean): SecurityFacts["csp"] {
  const directives: Record<string, string[]> = {};
  for (const part of raw.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    directives[name] = tokens.slice(1);
  }

  const scriptValues = [
    ...(directives["script-src"] ?? []),
    ...(directives["default-src"] ?? []),
  ].map((value) => value.toLowerCase());
  const allValues = Object.values(directives).flat().map((value) => value.toLowerCase());

  return {
    present: Boolean(raw),
    reportOnly,
    directives,
    unsafeInline: allValues.includes("'unsafe-inline'"),
    unsafeEval: allValues.includes("'unsafe-eval'"),
    wildcard: scriptValues.includes("*"),
    reportUri: Boolean(directives["report-uri"]?.length || directives["report-to"]?.length),
  };
}

function parseCookies(setCookies: string[]): SecurityFacts["cookies"] {
  return setCookies
    .map((raw) => {
      const parts = raw.split(";").map((part) => part.trim());
      const [nameValue] = parts;
      const name = nameValue?.split("=")[0]?.trim() ?? "";
      if (!name) return null;
      const lower = parts.map((part) => part.toLowerCase());
      const sameSitePart = parts.find((part) => /^samesite=/i.test(part));
      return {
        name,
        secure: lower.includes("secure"),
        httpOnly: lower.includes("httponly"),
        sameSite: sameSitePart ? sameSitePart.split("=")[1] ?? "" : "",
        prefixed: /^__(host|secure)-/i.test(name),
      };
    })
    .filter((cookie): cookie is SecurityFacts["cookies"][number] => cookie !== null);
}

async function checkLegal(baseUrl: string, html: HtmlFacts | null): Promise<SecurityFacts["legal"]> {
  const candidates = {
    privacy: ["/privacy", "/privacy-policy", "/privacy-notice"],
    terms: ["/terms", "/terms-and-conditions", "/terms-of-service"],
    cookies: ["/cookies", "/cookie-policy", "/cookie-notice"],
    accessibility: ["/accessibility", "/accessibility-statement"],
  };

  const linked = (paths: string[]) =>
    Boolean(
      html?.links.some((link) =>
        paths.some((path) => {
          try {
            return new URL(link.href).pathname.replace(/\/$/, "") === path;
          } catch {
            return false;
          }
        }),
      ),
    );

  const statuses: Record<string, number> = {};
  await Promise.all(
    Object.entries(candidates).flatMap(([group, paths]) =>
      paths.map(async (path) => {
        try {
          statuses[path] = await probeStatus(new URL(path, baseUrl).href, 5000);
        } catch {
          statuses[path] = 0;
        }
        return [group, path] as const;
      }),
    ),
  );

  const found = (paths: string[]) =>
    linked(paths) || paths.some((path) => (statuses[path] ?? 0) >= 200 && (statuses[path] ?? 0) < 400);

  return {
    privacy: found(candidates.privacy),
    terms: found(candidates.terms),
    cookies: found(candidates.cookies),
    accessibility: found(candidates.accessibility),
    statuses,
  };
}

/** Analyse response headers, cookies, CSP, forms and legal pages. */
export async function collectSecurity(
  baseUrl: string,
  transport: TransportFacts,
  html: HtmlFacts | null,
): Promise<SecurityFacts> {
  const headers = transport.homepage.headers;
  const cspHeader = headers["content-security-policy"] ?? "";
  const cspReportOnly = headers["content-security-policy-report-only"] ?? "";
  const csp = parseCsp(cspHeader || cspReportOnly, Boolean(!cspHeader && cspReportOnly));

  const externalScripts = html?.scripts.filter((script) => script.thirdParty) ?? [];
  const forms = (html?.forms ?? []).map((form) => {
    let insecure = false;
    try {
      if (form.action) insecure = new URL(form.action, transport.homepage.finalUrl).protocol === "http:";
    } catch {
      insecure = false;
    }
    return { ...form, insecure };
  });

  return {
    headers,
    csp,
    cookies: parseCookies(transport.homepage.setCookies),
    xcto: headers["x-content-type-options"] ?? "",
    frameOptions: headers["x-frame-options"] ?? "",
    referrerPolicy: headers["referrer-policy"] ?? "",
    permissionsPolicy: headers["permissions-policy"] ?? "",
    coop: headers["cross-origin-opener-policy"] ?? "",
    coep: headers["cross-origin-embedder-policy"] ?? "",
    corp: headers["cross-origin-resource-policy"] ?? "",
    sri: {
      externalScripts: externalScripts.length,
      withIntegrity: externalScripts.filter((script) => Boolean(script.integrity)).length,
    },
    forms,
    trackers: html?.analytics ?? [],
    consent: html?.consent ?? [],
    legal: await checkLegal(baseUrl, html),
    serverDisclosure: {
      server: headers.server ?? "",
      poweredBy: headers["x-powered-by"] ?? "",
    },
  };
}
