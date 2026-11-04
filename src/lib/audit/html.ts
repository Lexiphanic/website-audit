import { parseHTML } from "linkedom";
import { cleanText, sha256 } from "../util";
import { fetchBytes } from "./fetch";
import { detectFingerprints } from "./fingerprints";
import { detectThirdParties } from "./third-parties";
import type { HtmlFacts, HtmlImageFact, HtmlScriptFact, ThirdPartyFacts } from "./types";

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

export function imageDimensions(bytes: Uint8Array, contentType: string): {
  width: number;
  height: number;
  type: string;
} {
  const type = contentType.split(";")[0]?.toLowerCase() ?? "";
  try {
    if (bytes.length >= 24 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      return { width: view.getUint32(16), height: view.getUint32(20), type: "PNG" };
    }
    if (bytes.length >= 10 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
      return {
        width: bytes[6] | (bytes[7] << 8),
        height: bytes[8] | (bytes[9] << 8),
        type: "GIF",
      };
    }
    if (bytes.length > 30 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[8] === 0x57 && bytes[9] === 0x45) {
      const chunk = String.fromCharCode(bytes[12], bytes[13], bytes[14], bytes[15]);
      if (chunk === "VP8X") {
        return {
          width: 1 + (bytes[24] | (bytes[25] << 8) | (bytes[26] << 16)),
          height: 1 + (bytes[27] | (bytes[28] << 8) | (bytes[29] << 16)),
          type: "WebP",
        };
      }
      if (chunk === "VP8 " && bytes.length > 29) {
        return {
          width: (bytes[26] | (bytes[27] << 8)) & 0x3fff,
          height: (bytes[28] | (bytes[29] << 8)) & 0x3fff,
          type: "WebP",
        };
      }
    }
    if (bytes.length > 4 && bytes[0] === 0xff && bytes[1] === 0xd8) {
      let offset = 2;
      while (offset + 9 < bytes.length) {
        if (bytes[offset] !== 0xff) {
          offset += 1;
          continue;
        }
        const marker = bytes[offset + 1];
        const length = (bytes[offset + 2] << 8) | bytes[offset + 3];
        if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
          return {
            width: (bytes[offset + 7] << 8) | bytes[offset + 8],
            height: (bytes[offset + 5] << 8) | bytes[offset + 6],
            type: "JPEG",
          };
        }
        offset += 2 + length;
      }
    }
    if (type.includes("svg") || bytes.slice(0, 200).some((byte) => byte === 0x3c)) {
      const text = new TextDecoder().decode(bytes.slice(0, 4096));
      const width = /width=["']?([\d.]+)/i.exec(text)?.[1];
      const height = /height=["']?([\d.]+)/i.exec(text)?.[1];
      if (width && height) return { width: Number(width), height: Number(height), type: "SVG" };
    }
  } catch {
    // Unknown image format
  }
  return { width: 0, height: 0, type: type || "Unknown" };
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
): Promise<{ html: HtmlFacts; thirdParties: ThirdPartyFacts }> {
  const contentType = headers["content-type"] ?? "";
  const prefix = html.slice(0, 300).toLowerCase();
  if (status >= 400) {
    throw new Error(`Homepage returned ${status}`);
  }
  if (!html.trim()) {
    throw new Error("Homepage returned an empty body");
  }
  if (
    !contentType.includes("html") &&
    !prefix.includes("<!doctype") &&
    !prefix.includes("<html") &&
    !prefix.includes("<head")
  ) {
    throw new Error(`Homepage did not return HTML (${contentType || "unknown content type"})`);
  }

  let document: Document;
  try {
    ({ document } = parseHTML(html));
  } catch {
    throw new Error("Homepage HTML could not be parsed");
  }
  if (!document.documentElement) {
    throw new Error("Homepage HTML had no document element");
  }
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
  const fingerprints = detectFingerprints({ html, headers, url: finalUrl });
  const generator = first(meta, "generator");
  const platformFingerprint =
    fingerprints.find((item) => ["CMS", "Ecommerce", "Website builder"].includes(item.category)) ??
    fingerprints.find((item) => item.category === "Framework");
  const platform = platformFingerprint
    ? { platform: platformFingerprint.name, confidence: platformFingerprint.confidence }
    : generator
      ? { platform: cleanText(generator, 80), confidence: "medium" as const }
      : { platform: "Unknown / custom", confidence: "low" as const };
  const technologyGroups: Record<string, string[]> = {};
  for (const fingerprint of fingerprints) {
    (technologyGroups[fingerprint.category] ??= []).push(fingerprint.name);
  }

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
  let ogImageWidth = 0;
  let ogImageHeight = 0;
  let ogImageType = "";
  const ogImage = og["og:image"] ?? "";
  if (ogImage && !ogImage.startsWith("data:")) {
    try {
      const absoluteOg = new URL(ogImage, base).href;
      const image = await fetchBytes(absoluteOg, { maxBytes: 512_000 });
      ogImageStatus = image.status;
      const dimensions = imageDimensions(image.bytes, image.contentType);
      ogImageWidth = dimensions.width;
      ogImageHeight = dimensions.height;
      ogImageType = dimensions.type;
    } catch {
      ogImageStatus = 0;
    }
  }

  const facts: HtmlFacts = {
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
    technologies: fingerprints.map((item) => item.name),
    technologyGroups,
    analytics: fingerprints
      .filter((item) => ["Analytics", "Advertising", "Tag manager"].includes(item.category))
      .map((item) => item.name),
    consent: fingerprints
      .filter((item) => item.category === "Consent")
      .map((item) => item.name),
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
    ogImageWidth,
    ogImageHeight,
    ogImageType,
    bodyHash: await sha256(html),
  };

  const iframes = Array.from(document.querySelectorAll("iframe[src]"))
    .map((iframe) => iframe.getAttribute("src") ?? "")
    .filter(Boolean);
  const hints = Array.from(
    document.querySelectorAll('link[rel="preconnect"][href], link[rel="dns-prefetch"][href]'),
  )
    .map((link) => link.getAttribute("href") ?? "")
    .filter(Boolean);

  const thirdParties = detectThirdParties({
    url: finalUrl,
    headers,
    htmlSource: html,
    scripts: facts.scripts.map((script) => script.src),
    stylesheets: facts.stylesheets,
    images: facts.images.map((image) => image.src),
    iframes,
    hints,
  });

  return { html: facts, thirdParties };
}
