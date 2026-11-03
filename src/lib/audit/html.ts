import { parseHTML } from "linkedom";
import { cleanText, sha256 } from "../util";
import { probeStatus } from "./fetch";
import type { HtmlFacts, HtmlImageFact, HtmlScriptFact } from "./types";

function metaMap(document: Document): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const meta of Array.from(document.querySelectorAll("meta"))) {
    const key = (meta.getAttribute("property") ?? meta.getAttribute("name") ?? "").toLowerCase();
    const content = meta.getAttribute("content") ?? "";
    if (!key) continue;
    const values = map.get(key) ?? [];
    values.push(content);
    map.set(key, values);
  }
  return map;
}

function first(map: Map<string, string[]>, key: string): string {
  return map.get(key.toLowerCase())?.[0] ?? "";
}

function imageFormat(src: string): string {
  const match = /\.([a-z0-9]{2,5})(?:[?#]|$)/i.exec(src);
  const ext = match?.[1]?.toLowerCase() ?? "";
  if (ext === "jpg" || ext === "jpeg") return "JPEG";
  if (ext === "png") return "PNG";
  if (ext === "webp") return "WebP";
  if (ext === "avif") return "AVIF";
  if (ext === "gif") return "GIF";
  if (ext === "svg") return "SVG";
  if (ext === "ico") return "ICO";
  return ext ? ext.toUpperCase() : "Unknown";
}

function detectPlatform(
  html: string,
  document: Document,
  headers: Record<string, string>,
): { platform: string; confidence: "high" | "medium" | "low" } {
  const generator = first(metaMap(document), "generator").toLowerCase();
  const haystack = `${html.slice(0, 200_000)} ${Object.values(headers).join(" ")}`.toLowerCase();

  const tests: { name: string; test: RegExp; confidence: "high" | "medium" | "low" }[] = [
    { name: "WordPress", test: /wp-content|wp-includes|wp-json/i, confidence: "high" },
    { name: "WooCommerce", test: /woocommerce|wc-block|wc_add_to_cart/i, confidence: "high" },
    { name: "Shopify", test: /cdn\.shopify\.com|shopify\.theme|shopify-payment/i, confidence: "high" },
    { name: "Wix", test: /wixstatic\.com|wix\.com|parastorage/i, confidence: "high" },
    { name: "Squarespace", test: /squarespace\.com|static1\.squarespace/i, confidence: "high" },
    { name: "Webflow", test: /data-wf-site|webflow\.com|webflow\.js/i, confidence: "high" },
    { name: "Framer", test: /framerusercontent\.com|framer\.com/i, confidence: "medium" },
    { name: "GoDaddy Website Builder", test: /godaddy|websitebuilder/i, confidence: "medium" },
    { name: "Duda", test: /dudamobile|dudaone|duda\.co/i, confidence: "medium" },
    { name: "Ghost", test: /ghost\/|ghost\.org|ghost-url/i, confidence: "medium" },
    { name: "HubSpot CMS", test: /hubspot|hs-scripts\.com|hs_cos_wrapper/i, confidence: "medium" },
    { name: "Joomla", test: /joomla|com_content/i, confidence: "medium" },
    { name: "Drupal", test: /drupal|sites\/default\/files/i, confidence: "medium" },
    { name: "Magento", test: /magento|mage\/cookies|static\/version/i, confidence: "medium" },
    { name: "BigCommerce", test: /bigcommerce\.com|bc-sf-filter/i, confidence: "medium" },
    { name: "PrestaShop", test: /prestashop/i, confidence: "medium" },
  ];

  if (generator) {
    const byGenerator = tests.find((test) => generator.includes(test.name.toLowerCase().split(" ")[0]));
    if (byGenerator) return { platform: byGenerator.name, confidence: "high" };
    return { platform: cleanText(first(metaMap(document), "generator"), 80), confidence: "medium" };
  }

  const match = tests.find((test) => test.test.test(haystack));
  if (match) return { platform: match.name, confidence: match.confidence };
  return { platform: "Unknown / custom", confidence: "low" };
}

function detectAnalytics(html: string, document: Document): string[] {
  const sources = Array.from(document.querySelectorAll("script[src]"))
    .map((script) => script.getAttribute("src") ?? "")
    .join(" ");
  const haystack = `${sources} ${html.slice(0, 300_000)}`.toLowerCase();
  const found = new Set<string>();
  if (/googletagmanager\.com\/gtag\/js|gtag\(/.test(haystack)) found.add("Google Analytics 4");
  if (/googletagmanager\.com\/gtm\.js|gtm-/.test(haystack)) found.add("Google Tag Manager");
  if (/connect\.facebook\.net|fbq\(/.test(haystack)) found.add("Meta Pixel");
  if (/snap\.licdn\.com|linkedin insight/.test(haystack)) found.add("LinkedIn Insight");
  if (/static\.hotjar\.com|hj\(/.test(haystack)) found.add("Hotjar");
  if (/clarity\.ms/.test(haystack)) found.add("Microsoft Clarity");
  if (/plausible\.io/.test(haystack)) found.add("Plausible");
  if (/usefathom\.com/.test(haystack)) found.add("Fathom");
  if (/matomo|piwik/.test(haystack)) found.add("Matomo");
  if (/analytics\.tiktok\.com|ttq\./.test(haystack)) found.add("TikTok Pixel");
  if (/hs-scripts\.com|hubspot/.test(haystack)) found.add("HubSpot");
  return [...found];
}

function detectConsent(html: string): string[] {
  const haystack = html.slice(0, 400_000).toLowerCase();
  const found = new Set<string>();
  if (/onetrust|optanon/.test(haystack)) found.add("OneTrust");
  if (/cookiebot/.test(haystack)) found.add("Cookiebot");
  if (/cookieyes/.test(haystack)) found.add("CookieYes");
  if (/osano/.test(haystack)) found.add("Osano");
  if (/termly/.test(haystack)) found.add("Termly");
  if (/iubenda/.test(haystack)) found.add("iubenda");
  if (/complianz/.test(haystack)) found.add("Complianz");
  if (/borlabs/.test(haystack)) found.add("Borlabs");
  if (/usercentrics/.test(haystack)) found.add("Usercentrics");
  if (/cookieconsent|gdpr-cookie/.test(haystack)) found.add("Cookie consent script");
  return [...found];
}

function detectSocial(document: Document): string[] {
  const profiles = new Set<string>();
  for (const link of Array.from(document.querySelectorAll("a[href]"))) {
    const href = link.getAttribute("href") ?? "";
    const match = /^https?:\/\/(?:www\.)?(facebook|instagram|linkedin|x|twitter|youtube|tiktok|github|threads)\.com/i.exec(href);
    if (match) profiles.add(match[1].toLowerCase());
  }
  return [...profiles];
}

function extractEmails(document: Document, html: string): string[] {
  const found = new Set<string>();
  for (const link of Array.from(document.querySelectorAll('a[href^="mailto:"]'))) {
    const address = (link.getAttribute("href") ?? "").replace(/^mailto:/i, "").split("?")[0];
    if (address.includes("@")) found.add(address.toLowerCase());
  }
  for (const match of html.matchAll(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)) {
    if (found.size >= 10) break;
    found.add(match[0].toLowerCase());
  }
  return [...found].slice(0, 10);
}

function extractPhones(document: Document): string[] {
  const found = new Set<string>();
  for (const link of Array.from(document.querySelectorAll('a[href^="tel:"]'))) {
    const number = (link.getAttribute("href") ?? "").replace(/^tel:/i, "").trim();
    if (number) found.add(number);
  }
  return [...found].slice(0, 10);
}

function detectMixedContent(document: Document, baseUrl: string): string[] {
  const found = new Set<string>();
  if (!baseUrl.startsWith("https://")) return [];
  for (const element of Array.from(document.querySelectorAll("[src], [href], [poster]"))) {
    for (const attribute of ["src", "href", "poster"]) {
      const value = element.getAttribute(attribute) ?? "";
      if (/^http:\/\//i.test(value)) found.add(value);
    }
  }
  for (const style of Array.from(document.querySelectorAll("style"))) {
    const value = style.textContent ?? "";
    for (const match of value.matchAll(/url\(\s*['"]?(http:\/\/[^'")]+)/gi)) {
      found.add(match[1]);
    }
  }
  return [...found].slice(0, 20);
}

function jsonLdFacts(document: Document): HtmlFacts["jsonLd"] {
  const results: HtmlFacts["jsonLd"] = [];
  for (const script of Array.from(document.querySelectorAll('script[type="application/ld+json"]'))) {
    const raw = script.textContent ?? "";
    try {
      const data = JSON.parse(raw) as Record<string, unknown> | Record<string, unknown>[];
      const nodes = Array.isArray(data) ? data : [data];
      for (const node of nodes) {
        const graph = node["@graph"];
        if (Array.isArray(graph)) {
          for (const item of graph) {
            const type = (item as Record<string, unknown>)["@type"];
            results.push({ valid: true, type: String(type ?? "Unknown"), error: "" });
          }
        } else {
          results.push({ valid: true, type: String(node["@type"] ?? "Unknown"), error: "" });
        }
      }
    } catch (error) {
      results.push({
        valid: false,
        type: "Invalid JSON",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return results.slice(0, 20);
}

/** Parse the homepage HTML into the facts the checks need. */
export async function collectHtml(
  html: string,
  finalUrl: string,
  status: number,
  headers: Record<string, string> = {},
): Promise<HtmlFacts> {
  const { document } = parseHTML(html);
  const meta = metaMap(document);
  const base = new URL(finalUrl);

  const og: Record<string, string> = {};
  const twitter: Record<string, string> = {};
  for (const [key, values] of meta) {
    if (key.startsWith("og:")) og[key] = values[0] ?? "";
    if (key.startsWith("twitter:")) twitter[key] = values[0] ?? "";
  }

  const icons = Array.from(document.querySelectorAll('link[rel~="icon"], link[rel="apple-touch-icon"]'))
    .map((link) => ({
      rel: link.getAttribute("rel") ?? "",
      href: link.getAttribute("href") ?? "",
      sizes: link.getAttribute("sizes") ?? "",
      type: link.getAttribute("type") ?? "",
    }))
    .filter((icon) => icon.href);

  const manifestHref = document.querySelector('link[rel="manifest"]')?.getAttribute("href") ?? "";

  const hreflang = Array.from(document.querySelectorAll('link[rel="alternate"][hreflang]'))
    .map((link) => ({
      lang: link.getAttribute("hreflang") ?? "",
      href: link.getAttribute("href") ?? "",
    }))
    .filter((item) => item.lang);

  const headings = Array.from(document.querySelectorAll("h1, h2, h3, h4, h5, h6"))
    .map((heading) => ({
      level: Number(heading.tagName.slice(1)),
      text: cleanText(heading.textContent, 120),
    }))
    .filter((heading) => heading.text);

  const images: HtmlImageFact[] = Array.from(document.querySelectorAll("img"))
    .map((image) => {
      const src = image.getAttribute("src") ?? image.getAttribute("data-src") ?? "";
      return {
        src,
        alt: image.getAttribute("alt") ?? "",
        loading: image.getAttribute("loading") ?? "",
        width: image.getAttribute("width") ?? "",
        height: image.getAttribute("height") ?? "",
        format: imageFormat(src),
      };
    })
    .filter((image) => image.src);

  const scripts: HtmlScriptFact[] = Array.from(document.querySelectorAll("script"))
    .map((script) => {
      const src = script.getAttribute("src") ?? "";
      let thirdParty = false;
      if (src) {
        try {
          thirdParty = new URL(src, base).origin !== base.origin;
        } catch {
          thirdParty = false;
        }
      }
      return {
        src,
        integrity: script.getAttribute("integrity") ?? "",
        async: script.hasAttribute("async"),
        defer: script.hasAttribute("defer"),
        thirdParty,
      };
    })
    .filter((script) => script.src);

  const stylesheets = Array.from(document.querySelectorAll('link[rel="stylesheet"][href]'))
    .map((link) => link.getAttribute("href") ?? "")
    .filter(Boolean);

  const forms = Array.from(document.querySelectorAll("form")).map((form) => ({
    action: form.getAttribute("action") ?? "",
    method: (form.getAttribute("method") ?? "get").toLowerCase(),
  }));

  const links = Array.from(document.querySelectorAll("a[href]"))
    .map((link) => {
      const href = link.getAttribute("href") ?? "";
      let absolute = "";
      let internal = false;
      try {
        const url = new URL(href, base);
        absolute = url.href;
        internal = url.origin === base.origin;
      } catch {
        absolute = "";
      }
      return {
        href: absolute,
        text: cleanText(link.textContent, 100),
        internal,
      };
    })
    .filter((link) => link.href.startsWith("http"))
    .slice(0, 300);

  const bodyText = document.body?.textContent ?? "";
  const wordCount = bodyText.trim() ? bodyText.trim().split(/\s+/).length : 0;
  const platform = detectPlatform(html, document, headers);
  const charset =
    document.querySelector("meta[charset]")?.getAttribute("charset") ??
    (document.querySelector('meta[http-equiv="content-type" i]')?.getAttribute("content") ?? "").match(/charset=([^;]+)/i)?.[1] ??
    "";

  let duplicateMeta = 0;
  for (const values of meta.values()) {
    if (values.length > 1) duplicateMeta += values.length - 1;
  }
  duplicateMeta += Math.max(0, document.querySelectorAll('link[rel="canonical"]').length - 1);
  duplicateMeta += Math.max(0, document.querySelectorAll("title").length - 1);

  let ogImageStatus = 0;
  const ogImage = og["og:image"] ?? "";
  if (ogImage && !ogImage.startsWith("data:")) {
    try {
      const absoluteOg = new URL(ogImage, base).href;
      ogImageStatus = await probeStatus(absoluteOg);
    } catch {
      ogImageStatus = 0;
    }
  }

  return {
    finalUrl,
    status,
    title: cleanText(document.querySelector("title")?.textContent, 200),
    description: cleanText(first(meta, "description"), 400),
    canonical: document.querySelector('link[rel="canonical"]')?.getAttribute("href") ?? "",
    robots: first(meta, "robots"),
    lang: document.documentElement.getAttribute("lang") ?? "",
    charset,
    viewport: first(meta, "viewport"),
    themeColor: first(meta, "theme-color"),
    og,
    twitter,
    icons,
    manifestHref,
    jsonLd: jsonLdFacts(document),
    hreflang,
    headings,
    images,
    scripts,
    stylesheets,
    inlineStyleBytes: Array.from(document.querySelectorAll("style")).reduce(
      (total, style) => total + (style.textContent?.length ?? 0),
      0,
    ),
    forms,
    links,
    generator: first(meta, "generator"),
    platform: platform.platform,
    platformConfidence: platform.confidence,
    analytics: detectAnalytics(html, document),
    consent: detectConsent(html),
    social: detectSocial(document),
    emails: extractEmails(document, html),
    phones: extractPhones(document),
    wordCount,
    domSize: document.querySelectorAll("*").length,
    mixedContent: detectMixedContent(document, finalUrl),
    hasSkipLink: Boolean(document.querySelector('a[href="#main"], a.skip-link')),
    hasMain: Boolean(document.querySelector("main")),
    metaCount: document.querySelectorAll("meta").length,
    duplicateMeta,
    ogImageStatus,
    bodyHash: await sha256(html),
  };
}
