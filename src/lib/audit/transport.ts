import { followRedirects, fetchText } from "./fetch";
import { certificateFromCrt, startLabs, tlsFromLabs } from "./tls";
import type { DnsFacts, HstsInfo, TransportFacts } from "./types";

function parseHsts(raw: string): HstsInfo {
  const value = raw ?? "";
  const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(value);
  return {
    present: Boolean(value.trim()),
    raw: value,
    maxAge: maxAgeMatch ? Number(maxAgeMatch[1]) : null,
    includeSubDomains: /includeSubDomains/i.test(value),
    preload: /preload/i.test(value),
  };
}

function hstsFrom(headers: Record<string, string>): HstsInfo {
  return parseHsts(headers["strict-transport-security"] ?? "");
}

async function preloadStatus(domain: string): Promise<string | null> {
  try {
    const response = await fetch(
      `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(domain)}`,
      { signal: AbortSignal.timeout(6000) },
    );
    if (!response.ok) return null;
    const data = (await response.json()) as { status?: string };
    return data.status ?? null;
  } catch {
    return null;
  }
}

/** Collect the redirect matrix, TLS probes, HSTS and transport headers. */
export async function collectTransport(
  domain: string,
  dns: DnsFacts,
): Promise<TransportFacts> {
  const apex = `https://${domain}/`;
  const wwwHost = `www.${domain}`;
  const www = `https://${wwwHost}/`;

  const [httpApex, httpsApex, httpWww, httpsWww, pathProbe, indexProbe, notFoundProbe] = await Promise.all([
    followRedirects(`http://${domain}/`, { maxHops: 8 }),
    followRedirects(apex, { maxHops: 8, hashBody: true }),
    followRedirects(`http://${wwwHost}/`, { maxHops: 8 }),
    followRedirects(www, { maxHops: 8, hashBody: true }),
    followRedirects(`http://${domain}/lexiphanic-audit?x=1`, { maxHops: 8 }),
    followRedirects(`https://${domain}/index.html`, { maxHops: 8, hashBody: true }),
    followRedirects(`https://${domain}/lexiphanic-audit-${Date.now().toString(36)}`, { maxHops: 8 }),
  ]);

  const wwwReachable = httpsWww.hops.length > 0;

  const homepageUrl = httpsApex.finalUrl || (wwwReachable ? httpsWww.finalUrl : apex);
  let homepage: TransportFacts["homepage"] = {
    status: 0,
    finalUrl: homepageUrl,
    ttfbMs: 0,
    htmlBytes: 0,
    contentEncoding: "",
    headers: {},
    setCookies: [],
  };

  try {
    const response = await fetchText(homepageUrl, { timeoutMs: 10_000, maxBytes: 512_000 });
    homepage = {
      status: response.status,
      finalUrl: homepageUrl,
      ttfbMs: response.ttfbMs,
      htmlBytes: response.bytes || response.body.length,
      contentEncoding: response.headers["content-encoding"] ?? "",
      headers: response.headers,
      setCookies: response.setCookies,
    };
  } catch (error) {
    homepage.error = error instanceof Error ? error.message : String(error);
  }

  const tlsHost = (() => {
    try {
      return new URL(homepage.finalUrl).hostname;
    } catch {
      return domain;
    }
  })();

  const [crtCertificate, labs] = await Promise.all([
    certificateFromCrt(domain),
    startLabs(tlsHost),
  ]);
  const preload = await preloadStatus(domain);
  const apexTls = tlsFromLabs(labs, crtCertificate);
  const wwwTls = wwwReachable ? apexTls : null;

  const altSvc = homepage.headers["alt-svc"] ?? "";
  const http3 = /(?:^|,)\s*h3\s*=/i.test(altSvc);
  const ipv6 = dns.records.aaaa.length > 0;

  return {
    probes: [
      { ...httpApex, url: `http://${domain}/` },
      { ...httpsApex, url: apex },
      { ...httpWww, url: `http://${wwwHost}/` },
      { ...httpsWww, url: www },
    ],
    homepage,
    tls: { apex: apexTls, www: wwwTls },
    hsts: {
      apex: hstsFrom(httpsApex.firstHeaders),
      www: hstsFrom(httpsWww.firstHeaders),
      preloadStatus: preload,
    },
    ipv6,
    http2: labs.http2,
    http3,
    wwwReachable,
    pathProbe,
    indexProbe,
    notFoundProbe,
  };
}
