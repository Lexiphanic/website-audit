import { fetchText, probeStatus } from "./fetch";
import type {
  HtmlFacts,
  PerformanceFacts,
  PsiFacts,
  TransportFacts,
} from "./types";

function detectCdn(headers: Record<string, string>): string {
  if (headers["cf-ray"] || /cloudflare/i.test(headers.server ?? "")) return "Cloudflare";
  if (headers["x-vercel-id"] || headers["x-vercel-cache"]) return "Vercel";
  if (headers["x-nf-request-id"] || headers["x-netlify-id"]) return "Netlify";
  if (headers["x-amz-cf-id"] || headers["x-amz-cf-pop"]) return "Amazon CloudFront";
  if (headers["x-fastly-request-id"] || headers["x-served-by"]) return "Fastly";
  if (headers["x-github-request-id"]) return "GitHub Pages";
  if (headers["x-akamai-transformed"]) return "Akamai";
  return "None detected";
}

function absolute(value: string, base: string): string {
  try {
    return new URL(value, base).href;
  } catch {
    return "";
  }
}

async function headBytes(url: string): Promise<number> {
  try {
    const result = await fetchText(url, { method: "HEAD", timeoutMs: 5000, maxBytes: 0 });
    const length = Number(result.headers["content-length"] ?? 0);
    return Number.isFinite(length) && length > 0 ? length : 0;
  } catch {
    return 0;
  }
}

/**
 * The HTML fetch does not advertise compression, so its response is
 * uncompressed. Ask once more with a browser-like `Accept-Encoding` and read
 * only the headers; that is the answer a browser would actually receive.
 */
async function contentEncodingFor(url: string, fallback: string): Promise<string> {
  try {
    const result = await fetchText(url, {
      timeoutMs: 5000,
      maxBytes: 0,
      headers: { "accept-encoding": "br, gzip, zstd" },
    });
    return result.headers["content-encoding"] || fallback;
  } catch {
    return fallback;
  }
}

async function fontDisplay(html: HtmlFacts, transport: TransportFacts): Promise<string> {
  const cssUrls = html.stylesheets.slice(0, 3).map((href) => absolute(href, transport.homepage.finalUrl)).filter(Boolean);
  const bodies: string[] = [];
  for (const css of cssUrls) {
    try {
      const result = await fetchText(css, { timeoutMs: 6000, maxBytes: 256_000 });
      if (result.status === 200) bodies.push(result.body);
    } catch {
      // Ignore a stylesheet we cannot read.
    }
  }
  const joined = bodies.join("\n");
  if (!joined.includes("@font-face")) return "no web fonts detected";
  if (/font-display\s*:\s*swap/i.test(joined)) return "swap";
  if (/font-display\s*:\s*optional/i.test(joined)) return "optional";
  if (/font-display\s*:\s*fallback/i.test(joined)) return "fallback";
  if (/font-display\s*:\s*block/i.test(joined)) return "block";
  if (/font-display\s*:\s*auto/i.test(joined)) return "auto";
  return "not set";
}

async function brokenImages(html: HtmlFacts, transport: TransportFacts): Promise<string[]> {
  const urls = html.images
    .map((image) => absolute(image.src, transport.homepage.finalUrl))
    .filter((url) => url.startsWith("http"))
    .slice(0, 8);
  const broken: string[] = [];
  await Promise.all(
    urls.map(async (url) => {
      try {
        const status = await probeStatus(url, 5000);
        if (status >= 400 || status === 0) broken.push(url);
      } catch {
        broken.push(url);
      }
    }),
  );
  return broken.slice(0, 8);
}

async function brokenLinks(html: HtmlFacts, transport: TransportFacts): Promise<string[]> {
  const homepage = transport.homepage.finalUrl.replace(/\/$/, "");
  const urls = html.links
    .filter((link) => link.internal && link.href.startsWith("http"))
    .map((link) => link.href.split("#")[0])
    .filter((url) => url && url.replace(/\/$/, "") !== homepage)
    .slice(0, 6);
  const broken: string[] = [];
  await Promise.all(
    urls.map(async (url) => {
      try {
        const status = await probeStatus(url, 5000);
        if (status >= 400 || status === 0) broken.push(url);
      } catch {
        broken.push(url);
      }
    }),
  );
  return [...new Set(broken)].slice(0, 6);
}

function psiNumber(audits: Record<string, { displayValue?: string; numericValue?: number }>, key: string): string {
  const audit = audits[key];
  return audit?.displayValue ?? (typeof audit?.numericValue === "number" ? String(Math.round(audit.numericValue)) : "—");
}

async function collectPsi(domain: string, apiKey: string): Promise<PsiFacts | null> {
  const categories = ["performance", "accessibility", "best-practices", "seo"]
    .map((category) => `category=${category}`)
    .join("&");
  const url = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(`https://${domain}/`)}&strategy=mobile&${categories}&key=${encodeURIComponent(apiKey)}`;

  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(70_000) });
    if (!response.ok) {
      return {
        performance: null,
        accessibility: null,
        bestPractices: null,
        seo: null,
        lcp: "—",
        cls: "—",
        inp: "—",
        ttfb: "—",
        fcp: "—",
        tbt: "—",
        fieldData: "",
        error: `PageSpeed Insights returned ${response.status}`,
      };
    }
    const data = (await response.json()) as {
      lighthouseResult?: {
        categories?: Record<string, { score?: number }>;
        audits?: Record<string, { displayValue?: string; numericValue?: number }>;
      };
      loadingExperience?: {
        metrics?: Record<string, { category?: string; percentile?: number }>;
      };
    };
    const categoriesData = data.lighthouseResult?.categories ?? {};
    const audits = data.lighthouseResult?.audits ?? {};
    const score = (key: string) => {
      const value = categoriesData[key]?.score;
      return typeof value === "number" ? Math.round(value * 100) : null;
    };

    const field = data.loadingExperience?.metrics ?? {};
    const fieldParts = [
      field.LARGEST_CONTENTFUL_PAINT_MS
        ? `LCP ${field.LARGEST_CONTENTFUL_PAINT_MS.category?.toLowerCase() ?? ""}`
        : "",
      field.CUMULATIVE_LAYOUT_SHIFT_SCORE
        ? `CLS ${field.CUMULATIVE_LAYOUT_SHIFT_SCORE.category?.toLowerCase() ?? ""}`
        : "",
      field.INTERACTION_TO_NEXT_PAINT
        ? `INP ${field.INTERACTION_TO_NEXT_PAINT.category?.toLowerCase() ?? ""}`
        : "",
    ].filter(Boolean);

    return {
      performance: score("performance"),
      accessibility: score("accessibility"),
      bestPractices: score("best-practices"),
      seo: score("seo"),
      lcp: psiNumber(audits, "largest-contentful-paint"),
      cls: psiNumber(audits, "cumulative-layout-shift"),
      inp: psiNumber(audits, "interaction-to-next-paint"),
      ttfb: psiNumber(audits, "server-response-time"),
      fcp: psiNumber(audits, "first-contentful-paint"),
      tbt: psiNumber(audits, "total-blocking-time"),
      fieldData: fieldParts.join(" · "),
    };
  } catch (error) {
    return {
      performance: null,
      accessibility: null,
      bestPractices: null,
      seo: null,
      lcp: "—",
      cls: "—",
      inp: "—",
      ttfb: "—",
      fcp: "—",
      tbt: "—",
      fieldData: "",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/** Own performance measurements, plus optional Lighthouse/CrUX from PSI. */
export async function collectPerformance(
  domain: string,
  transport: TransportFacts,
  html: HtmlFacts,
  psiApiKey?: string,
): Promise<PerformanceFacts> {
  const headers = transport.homepage.headers;
  // Module scripts are deferred by default, so they do not block first paint.
  const renderBlockingUrls = [
    ...html.stylesheets,
    ...html.scripts
      .filter((script) => !script.async && !script.defer && !script.module)
      .map((script) => script.src),
  ].filter(Boolean);

  const assetUrls = [
    ...html.stylesheets.slice(0, 4),
    ...html.scripts.slice(0, 4).map((script) => script.src),
    ...html.images.slice(0, 3).map((image) => image.src),
  ]
    .map((value) => absolute(value, transport.homepage.finalUrl))
    .filter(Boolean);

  const [assetBytes, broken, badLinks, fonts, psi] = await Promise.all([
    Promise.all(assetUrls.slice(0, 8).map(headBytes)),
    brokenImages(html, transport),
    brokenLinks(html, transport),
    fontDisplay(html, transport),
    psiApiKey ? collectPsi(domain, psiApiKey) : Promise.resolve(null),
  ]);

  const imageFormats: Record<string, number> = {};
  for (const image of html.images) {
    imageFormats[image.format] = (imageFormats[image.format] ?? 0) + 1;
  }

  const thirdParty = new Set<string>();
  for (const script of html.scripts) {
    if (!script.src) continue;
    try {
      const url = new URL(script.src, transport.homepage.finalUrl);
      if (url.origin !== new URL(transport.homepage.finalUrl).origin) thirdParty.add(url.hostname);
    } catch {
      // ignore
    }
  }
  for (const stylesheet of html.stylesheets) {
    try {
      const url = new URL(stylesheet, transport.homepage.finalUrl);
      if (url.origin !== new URL(transport.homepage.finalUrl).origin) thirdParty.add(url.hostname);
    } catch {
      // ignore
    }
  }

  const contentEncoding = await contentEncodingFor(
    transport.homepage.finalUrl,
    transport.homepage.contentEncoding,
  );

  return {
    ttfbMs: transport.homepage.ttfbMs,
    htmlBytes: transport.homepage.htmlBytes,
    contentEncoding,
    renderBlocking: renderBlockingUrls.length,
    renderBlockingUrls: renderBlockingUrls.slice(0, 10),
    assetBytes: assetBytes.reduce((total, value) => total + value, 0),
    assetCount: assetUrls.length,
    imageFormats,
    fontDisplay: fonts,
    thirdPartyDomains: [...thirdParty].slice(0, 20),
    domSize: html.domSize,
    cacheControl: headers["cache-control"] ?? "",
    cdn: detectCdn(headers),
    brokenImages: broken,
    brokenLinks: badLinks,
    psi,
  };
}
