import { XMLParser } from "fast-xml-parser";
import { parseHTML } from "linkedom";
import { cleanText } from "../util";
import { fetchFollowing, fetchText, probeStatus } from "./fetch";
import {
  detectThirdParties,
  emptyThirdPartyFacts,
  mergeThirdPartyFacts,
} from "./third-parties";
import type {
  FileEntryFact,
  FilesFacts,
  HtmlFacts,
  IconFact,
  ManifestFacts,
  SitemapPageFact,
  ThirdPartyFacts,
} from "./types";

interface RawFile {
  entry: FileEntryFact;
  body: string;
}

const WELL_KNOWN_PATHS = [
  "/robots.txt",
  "/sitemap.xml",
  "/sitemap-index.xml",
  "/llms.txt",
  "/llms-full.txt",
  "/ai.txt",
  "/humans.txt",
  "/ads.txt",
  "/app-ads.txt",
  "/browserconfig.xml",
  "/manifest.webmanifest",
  "/site.webmanifest",
  "/favicon.ico",
  "/apple-touch-icon.png",
  "/.well-known/security.txt",
  "/security.txt",
  "/.well-known/llms.txt",
  "/.well-known/change-password",
  "/.well-known/apple-app-site-association",
  "/.well-known/assetlinks.json",
  "/.well-known/mta-sts.txt",
  "/.well-known/gpc.json",
  "/.well-known/trust.txt",
  "/.well-known/nodeinfo",
  "/.well-known/webfinger",
  "/.well-known/host-meta",
];

async function mapLimit<T, R>(
  values: T[],
  limit: number,
  mapper: (value: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = [];
  let index = 0;
  async function worker() {
    while (index < values.length) {
      const current = values[index];
      index += 1;
      results.push(await mapper(current));
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, worker));
  return results;
}

function looksLikeHtml(body: string, contentType: string): boolean {
  const prefix = body.slice(0, 300).toLowerCase();
  return (
    contentType.includes("text/html") ||
    prefix.includes("<!doctype html") ||
    prefix.includes("<html") ||
    prefix.includes("<head")
  );
}

function parseSecurityTxt(body: string): Record<string, string[]> {
  const fields: Record<string, string[]> = {};
  for (const line of body.split(/\r?\n/)) {
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const index = line.indexOf(":");
    if (index < 1) continue;
    const key = line.slice(0, index).trim().toLowerCase();
    const value = line.slice(index + 1).trim();
    if (!key || !value) continue;
    fields[key] = [...(fields[key] ?? []), value];
  }
  return fields;
}

interface RobotsResult {
  sitemaps: string[];
  blocksAll: boolean;
  blockedPaths: string[];
  aiRules: Record<string, string[] | null>;
}

function parseRobots(body: string): RobotsResult {
  const lines = body.split(/\r?\n/).map((line) => line.replace(/#.*$/, "").trim());
  const sitemaps: string[] = [];
  const groups: { agents: string[]; rules: { allow: boolean; path: string }[] }[] = [];
  let current: { agents: string[]; rules: { allow: boolean; path: string }[] } | null = null;

  for (const line of lines) {
    if (!line) continue;
    const [rawKey, ...rest] = line.split(":");
    const key = rawKey.trim().toLowerCase();
    const value = rest.join(":").trim();
    if (key === "sitemap" && value) {
      sitemaps.push(value);
      continue;
    }
    if (key === "user-agent") {
      if (!current || current.rules.length) {
        current = { agents: [], rules: [] };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      continue;
    }
    if ((key === "allow" || key === "disallow") && current && value !== undefined) {
      current.rules.push({ allow: key === "allow", path: value });
    }
  }

  const wildcard = groups.find((group) => group.agents.includes("*"));
  const disallows = wildcard?.rules.filter((rule) => !rule.allow && rule.path) ?? [];
  const allows = wildcard?.rules.filter((rule) => rule.allow && rule.path) ?? [];
  const blocksAll =
    disallows.some((rule) => rule.path === "/") &&
    !allows.some((rule) => rule.path === "/" || rule.path === "");

  const aiRules: Record<string, string[] | null> = {};
  for (const bot of ["gptbot", "claudebot", "perplexitybot", "google-extended", "ccbot", "bytespider", "amazonbot"]) {
    const group = groups.find((item) => item.agents.some((agent) => agent.includes(bot)));
    aiRules[bot] = group ? group.rules.map((rule) => `${rule.allow ? "Allow" : "Disallow"}: ${rule.path}`) : null;
  }

  return {
    sitemaps,
    blocksAll,
    blockedPaths: disallows.map((rule) => rule.path).slice(0, 20),
    aiRules,
  };
}

interface SitemapResult {
  valid: boolean;
  urls: string[];
  lastmod: string;
}

const parser = new XMLParser({
  ignoreAttributes: false,
  removeNSPrefix: true,
  trimValues: true,
});

function asArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function parseSitemap(body: string): {
  valid: boolean;
  urls: string[];
  children: string[];
  lastmod: string;
} {
  try {
    const parsed = parser.parse(body) as Record<string, unknown>;
    const urlset = parsed.urlset as Record<string, unknown> | undefined;
    const index = parsed.sitemapindex as Record<string, unknown> | undefined;
    if (!urlset && !index) return { valid: false, urls: [], children: [], lastmod: "" };

    const urls: string[] = [];
    const children: string[] = [];
    let lastmod = "";

    for (const item of asArray((urlset?.url ?? []) as Record<string, unknown> | Record<string, unknown>[])) {
      const loc = typeof item.loc === "string" ? item.loc : "";
      if (loc) urls.push(loc);
      const modified = typeof item.lastmod === "string" ? item.lastmod : "";
      if (modified > lastmod) lastmod = modified;
    }
    for (const item of asArray((index?.sitemap ?? []) as Record<string, unknown> | Record<string, unknown>[])) {
      const loc = typeof item.loc === "string" ? item.loc : "";
      if (loc) children.push(loc);
      const modified = typeof item.lastmod === "string" ? item.lastmod : "";
      if (modified > lastmod) lastmod = modified;
    }

    return { valid: true, urls, children, lastmod };
  } catch {
    return { valid: false, urls: [], children: [], lastmod: "" };
  }
}

async function sampleUrls(urls: string[]): Promise<FilesFacts["sitemaps"]["sample"]> {
  const sample = urls.slice(0, 10);
  return mapLimit(sample, 5, async (url) => {
    try {
      const status = await probeStatus(url, 6000);
      return { url, status };
    } catch (error) {
      return { url, status: 0, error: error instanceof Error ? error.message : String(error) };
    }
  });
}

const NON_HTML_EXTENSION =
  /\.(?:jpe?g|png|gif|webp|avif|svg|ico|bmp|tiff?|pdf|zip|gz|tgz|7z|rar|mp4|m4v|mov|webm|mp3|ogg|wav|woff2?|ttf|otf|eot|css|js|mjs|json|xml|rss|atom|txt|csv|docx?|xlsx?|pptx?)$/i;

function isHtmlUrl(url: string): boolean {
  try {
    return !NON_HTML_EXTENSION.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

/** Fetch a few sampled HTML pages for title, description, canonical and robots; not a crawl. */
async function samplePages(
  urls: string[],
): Promise<{ pages: SitemapPageFact[]; thirdParties: ThirdPartyFacts }> {
  const candidates = urls.filter(isHtmlUrl).slice(0, 5);
  const sampled = await mapLimit(candidates, 2, async (url) => {
    try {
      const result = await fetchFollowing(url, { timeoutMs: 7000, maxBytes: 64_000 });
      if (result.status !== 200 || !result.body) return null;
      // Sitemaps can include images and PDFs; only HTML pages have these tags.
      if (!/text\/html|application\/xhtml/i.test(result.contentType)) return null;
      const { document } = parseHTML(result.body);
      const metas = Array.from(document.querySelectorAll("meta"));
      const metaContent = (name: string) =>
        metas
          .find((meta) => (meta.getAttribute("name") ?? "").toLowerCase() === name)
          ?.getAttribute("content") ?? "";
      const canonical =
        Array.from(document.querySelectorAll("link"))
          .find((link) =>
            (link.getAttribute("rel") ?? "")
              .toLowerCase()
              .split(/\s+/)
              .includes("canonical"),
          )
          ?.getAttribute("href") ?? "";
      const resources = (selector: string, attribute: string) =>
        Array.from(document.querySelectorAll(selector))
          .map((element) => element.getAttribute(attribute) ?? "")
          .filter(Boolean);

      const page: SitemapPageFact = {
        url,
        title: cleanText(document.querySelector("title")?.textContent ?? "", 200),
        description: cleanText(metaContent("description"), 300),
        canonical,
        robots: metaContent("robots"),
        xRobots: result.headers["x-robots-tag"] ?? "",
      };
      const thirdParties = detectThirdParties({
        url,
        htmlSource: result.body,
        scripts: resources("script[src]", "src"),
        stylesheets: resources('link[rel="stylesheet"][href]', "href"),
        images: resources("img[src]", "src"),
        iframes: resources("iframe[src]", "src"),
        hints: resources('link[rel="preconnect"][href], link[rel="dns-prefetch"][href]', "href"),
      });
      return { page, thirdParties };
    } catch {
      return null;
    }
  });
  const entries = sampled.filter(
    (entry): entry is { page: SitemapPageFact; thirdParties: ThirdPartyFacts } => entry !== null,
  );
  return {
    pages: entries.map((entry) => entry.page),
    thirdParties: mergeThirdPartyFacts(...entries.map((entry) => entry.thirdParties)),
  };
}

function markdownStats(body: string): { headings: number; links: number } {
  let headings = 0;
  let links = 0;
  for (const line of body.split(/\r?\n/)) {
    if (/^#{1,6}\s+\S/.test(line)) headings += 1;
    if (/\]\([^)]+\)/.test(line)) links += 1;
  }
  return { headings, links };
}

function validJson(body: string): boolean {
  try {
    JSON.parse(body);
    return true;
  } catch {
    return false;
  }
}

const EMPTY_MANIFEST: ManifestFacts = {
  present: false,
  href: "",
  status: 0,
  valid: false,
  name: "",
  shortName: "",
  startUrl: "",
  display: "",
  themeColor: "",
  backgroundColor: "",
  icons: [],
  iconSizes: [],
};

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** Fetch and parse the web app manifest declared by the page (or the usual names). */
async function collectManifest(
  baseUrl: string,
  html: HtmlFacts | null,
  reusable: Map<string, string>,
  entries: Record<string, FileEntryFact>,
): Promise<ManifestFacts> {
  const base = new URL(baseUrl);
  const declaredHref = html?.manifestHref
    ? new URL(html.manifestHref, base).href
    : "";
  const candidates = [
    declaredHref,
    new URL("/manifest.webmanifest", base).href,
    new URL("/site.webmanifest", base).href,
    new URL("/manifest.json", base).href,
  ].filter(Boolean);

  for (const candidate of [...new Set(candidates)]) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(candidate);
    } catch {
      continue;
    }
    const sameOrigin = parsedUrl.origin === base.origin;
    const path = parsedUrl.pathname;

    // The well-known pass only speaks for this origin. A manifest on a CDN is
    // fetched directly rather than reusing a same-named local file.
    const known = sameOrigin ? entries[path] : undefined;
    if (known && (known.status !== 200 || known.soft404)) continue;

    let body: string | null = sameOrigin ? (reusable.get(path) ?? null) : null;
    let status = known?.status ?? 0;
    if (body === null) {
      try {
        const response = await fetchFollowing(candidate, { timeoutMs: 7000, maxBytes: 128_000 });
        status = response.status;
        if (response.status !== 200) continue;
        body = response.body;
      } catch {
        continue;
      }
    }

    try {
      const data = JSON.parse(body) as Record<string, unknown>;
      if (!data || typeof data !== "object" || Array.isArray(data)) {
        throw new Error("Manifest is not a JSON object");
      }

      const rawIcons = Array.isArray(data.icons) ? data.icons : [];
      const icons = rawIcons
        .filter(
          (icon): icon is Record<string, unknown> =>
            Boolean(icon) && typeof icon === "object" && !Array.isArray(icon),
        )
        .map((icon) => ({
          src: text(icon.src),
          sizes: text(icon.sizes),
          type: text(icon.type),
          purpose: text(icon.purpose),
        }))
        .filter((icon) => icon.src)
        .slice(0, 12);
      const iconSizes = [
        ...new Set(
          icons
            .flatMap((icon) => icon.sizes.split(/\s+/))
            .filter((size) => /^\d+x\d+$/i.test(size))
            .map((size) => size.toLowerCase()),
        ),
      ];

      return {
        present: true,
        href: candidate,
        status,
        valid: true,
        name: text(data.name),
        shortName: text(data.short_name),
        startUrl: text(data.start_url),
        display: text(data.display),
        themeColor: text(data.theme_color),
        backgroundColor: text(data.background_color),
        icons,
        iconSizes,
      };
    } catch (error) {
      return {
        ...EMPTY_MANIFEST,
        present: true,
        href: candidate,
        status: status || 200,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  if (declaredHref) {
    return {
      ...EMPTY_MANIFEST,
      present: true,
      href: declaredHref,
      error: "The declared manifest could not be read",
    };
  }
  return { ...EMPTY_MANIFEST };
}

/** Status and content type of one declared icon, without downloading the file. */
async function probeIcon(
  icon: { rel: string; href: string; sizes: string; type: string },
  baseUrl: string,
): Promise<IconFact> {
  let href = icon.href;
  try {
    href = new URL(icon.href, baseUrl).href;
  } catch {
    // Keep the original href so the check can still report what was declared.
  }

  try {
    const result = await fetchText(href, { method: "GET", timeoutMs: 5000, maxBytes: 0 });
    return {
      rel: icon.rel,
      href,
      sizes: icon.sizes,
      declaredType: icon.type,
      status: result.status,
      contentType: result.contentType,
      bytes: Number(result.headers["content-length"] ?? 0) || 0,
    };
  } catch (error) {
    return {
      rel: icon.rel,
      href,
      sizes: icon.sizes,
      declaredType: icon.type,
      status: 0,
      contentType: "",
      bytes: 0,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function collectIcons(
  baseUrl: string,
  html: HtmlFacts | null,
): Promise<{ appleTouch: IconFact[]; mask: IconFact | null }> {
  const icons = html?.icons ?? [];
  const sizeOf = (sizes: string): number =>
    sizes.split(/\s+/).reduce((largest, size) => {
      const match = /^(\d+)x(\d+)$/i.exec(size);
      return match ? Math.max(largest, Math.min(Number(match[1]), Number(match[2]))) : largest;
    }, 0);
  const apple = icons
    .filter((icon) => /apple-touch-icon/i.test(icon.rel))
    .sort((a, b) => sizeOf(b.sizes) - sizeOf(a.sizes))
    .slice(0, 4);
  const mask = icons.find((icon) => /(^|\s)mask-icon(\s|$)/i.test(icon.rel));

  const [appleTouch, maskIcon] = await Promise.all([
    Promise.all(apple.map((icon) => probeIcon(icon, baseUrl))),
    mask ? probeIcon(mask, baseUrl) : Promise.resolve(null),
  ]);

  return { appleTouch, mask: maskIcon };
}

/** Fetch robots, sitemaps and the well-known set, and parse what matters. */
export async function collectFiles(
  baseUrl: string,
  html: HtmlFacts | null,
  initialThirdParties: ThirdPartyFacts | null = null,
): Promise<FilesFacts> {
  const base = new URL(baseUrl);
  const fileUrl = (path: string) => new URL(path, base).href;

  const raws = await mapLimit(WELL_KNOWN_PATHS, 8, async (path): Promise<RawFile> => {
    try {
      const result = await fetchFollowing(fileUrl(path), {
        timeoutMs: 7000,
        maxBytes: 128_000,
        headers: { accept: "text/plain,application/xml,application/json,*/*;q=0.5" },
      });
      const soft404 =
        result.status === 200 &&
        !path.startsWith("/favicon") &&
        !path.startsWith("/apple-touch-icon") &&
        looksLikeHtml(result.body, result.contentType);
      return {
        entry: {
          path,
          status: result.status,
          contentType: result.contentType,
          bytes: result.bytes,
          soft404,
        },
        body: result.body,
      };
    } catch (error) {
      return {
        entry: {
          path,
          status: 0,
          contentType: "",
          bytes: 0,
          soft404: false,
          error: error instanceof Error ? error.message : String(error),
        },
        body: "",
      };
    }
  });

  const byPath = new Map(raws.map((raw) => [raw.entry.path, raw]));
  const entries: Record<string, FileEntryFact> = {};
  for (const raw of raws) entries[raw.entry.path] = raw.entry;

  // Bodies already fetched by the well-known pass, but only when the response
  // fits inside its 128 KB cap. A larger sitemap was truncated there and must
  // be fetched again with the bigger limit.
  const reusable = new Map<string, string>();
  for (const raw of raws) {
    if (
      raw.entry.status === 200 &&
      !raw.entry.soft404 &&
      raw.entry.bytes > 0 &&
      raw.entry.bytes < 128_000
    ) {
      reusable.set(raw.entry.path, raw.body);
    }
  }

  const get = (path: string): RawFile | undefined => {
    const raw = byPath.get(path);
    if (!raw || raw.entry.status === 0 || raw.entry.soft404) return undefined;
    return raw;
  };
  const ok = (path: string) => {
    const entry = entries[path];
    return Boolean(entry && entry.status >= 200 && entry.status < 400 && !entry.soft404);
  };

  // The manifest and declared icons do not depend on the sitemap work, so start
  // them now and await both at the end.
  const manifestPromise = collectManifest(base.href, html, reusable, entries);
  const iconsPromise = collectIcons(base.href, html);

  const robotsRaw = get("/robots.txt");
  const robots = robotsRaw
    ? parseRobots(robotsRaw.body)
    : { sitemaps: [], blocksAll: false, blockedPaths: [], aiRules: {} };

  // Prefer a sitemap advertised in robots.txt, then the usual candidates.
  const candidates = [...new Set([...robots.sitemaps, new URL("/sitemap.xml", base).href, new URL("/sitemap-index.xml", base).href])];
  const sitemap: SitemapResult & { source: string } = { valid: false, urls: [], lastmod: "", source: "" };

  for (const candidate of candidates) {
    try {
      let body: string | null = null;
      try {
        body = reusable.get(new URL(candidate).pathname) ?? null;
      } catch {
        body = null;
      }
      if (body === null) {
        const response = await fetchFollowing(candidate, { timeoutMs: 8000, maxBytes: 4_000_000 });
        if (response.status !== 200) continue;
        body = response.body;
      }
      const parsed = parseSitemap(body);
      if (!parsed.valid) continue;

      sitemap.valid = true;
      sitemap.source = candidate;
      sitemap.lastmod = parsed.lastmod;

      if (parsed.urls.length) {
        sitemap.urls = parsed.urls;
        break;
      }

      if (parsed.children.length) {
        for (const child of parsed.children.slice(0, 5)) {
          try {
            const childResponse = await fetchFollowing(child, { timeoutMs: 8000, maxBytes: 4_000_000 });
            if (childResponse.status !== 200) continue;
            const childParsed = parseSitemap(childResponse.body);
            sitemap.urls.push(...childParsed.urls);
            if (childParsed.lastmod > sitemap.lastmod) sitemap.lastmod = childParsed.lastmod;
          } catch {
            // Skip a broken child sitemap; the index itself is still valid.
          }
        }
        break;
      }
    } catch {
      // try the next candidate
    }
  }

  const uniqueUrls = [...new Set(sitemap.urls)];
  const securityWellKnown = get("/.well-known/security.txt");
  const securityRoot = get("/security.txt");
  const securityRaw = securityWellKnown ?? securityRoot;
  const securityFields = securityRaw ? parseSecurityTxt(securityRaw.body) : {};
  const expires = securityFields.expires?.[0] ?? "";
  const securityExpired = Boolean(expires && new Date(expires).valueOf() < Date.now());

  const llmsRoot = get("/llms.txt");
  const llmsWellKnown = get("/.well-known/llms.txt");
  const llmsSource = llmsRoot ?? llmsWellKnown;
  const llmsStats = markdownStats(llmsSource?.body ?? "");

  const [manifestDetails, iconFacts] = await Promise.all([manifestPromise, iconsPromise]);
  const [sample, sampled] = await Promise.all([
    uniqueUrls.length ? sampleUrls(uniqueUrls) : Promise.resolve([]),
    uniqueUrls.length
      ? samplePages(uniqueUrls)
      : Promise.resolve({ pages: [], thirdParties: emptyThirdPartyFacts() }),
  ]);
  const pages = sampled.pages;
  const thirdParties = mergeThirdPartyFacts(initialThirdParties, sampled.thirdParties);
  const titleCounts = new Map<string, number>();
  for (const entry of pages) {
    const key = entry.title.trim().toLowerCase();
    if (!key) continue;
    titleCounts.set(key, (titleCounts.get(key) ?? 0) + 1);
  }
  const duplicateTitles = [...titleCounts.entries()]
    .filter(([, count]) => count > 1)
    .map(([title]) => title)
    .slice(0, 5);

  return {
    entries,
    robots: {
      present: Boolean(robotsRaw),
      status: entries["/robots.txt"]?.status ?? 0,
      sitemaps: robots.sitemaps,
      blocksAll: robots.blocksAll,
      blockedPaths: robots.blockedPaths,
      aiRules: robots.aiRules,
    },
    sitemaps: {
      present: Boolean(sitemap.source),
      valid: sitemap.valid,
      urls: uniqueUrls.slice(0, 5000),
      count: uniqueUrls.length,
      sample,
      pages,
      duplicateTitles,
      lastmod: sitemap.lastmod,
      source: sitemap.source,
    },
    securityTxt: {
      present: Boolean(securityRaw),
      path: securityWellKnown ? "/.well-known/security.txt" : securityRoot ? "/security.txt" : "",
      fields: securityFields,
      expired: securityExpired,
      canonical: securityFields.canonical?.[0] ?? "",
      contentType: securityRaw?.entry.contentType ?? "",
    },
    llms: {
      root: Boolean(llmsRoot),
      wellKnown: Boolean(llmsWellKnown),
      full: ok("/llms-full.txt"),
      bytes: llmsSource?.entry.bytes ?? 0,
      headings: llmsStats.headings,
      links: llmsStats.links,
    },
    aiTxt: ok("/ai.txt"),
    changePassword: ok("/.well-known/change-password"),
    aasa: ok("/.well-known/apple-app-site-association") && validJson(get("/.well-known/apple-app-site-association")?.body ?? ""),
    assetlinks: ok("/.well-known/assetlinks.json") && validJson(get("/.well-known/assetlinks.json")?.body ?? ""),
    mtaSts: ok("/.well-known/mta-sts.txt"),
    gpc: ok("/.well-known/gpc.json") && validJson(get("/.well-known/gpc.json")?.body ?? ""),
    trustTxt: ok("/.well-known/trust.txt"),
    nodeinfo: ok("/.well-known/nodeinfo"),
    webfinger: ok("/.well-known/webfinger"),
    hostMeta: ok("/.well-known/host-meta"),
    humansTxt: ok("/humans.txt"),
    adsTxt: ok("/ads.txt"),
    appAdsTxt: ok("/app-ads.txt"),
    browserconfig: ok("/browserconfig.xml"),
    manifest: manifestDetails.present,
    manifestDetails,
    rootIcons: {
      favicon: ok("/favicon.ico"),
      appleTouch: ok("/apple-touch-icon.png"),
    },
    appleTouchIcons: iconFacts.appleTouch,
    maskIcon: iconFacts.mask,
    thirdParties,
  };
}
