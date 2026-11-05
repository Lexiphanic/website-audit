import { XMLParser } from "fast-xml-parser";
import { parseHTML } from "linkedom";
import { getDomain } from "tldts";
import { fetchFollowing, fetchText, followRedirects } from "./fetch";
import {
  detectThirdParties,
  emptyThirdPartyFacts,
  mergeThirdPartyFacts,
} from "./third-parties";
import type { FileEntryFact, FilesFacts, HtmlFacts, ThirdPartyFacts } from "./types";

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

function looksLikeHtml(body: string, contentType: string): boolean {  const prefix = body.slice(0, 300).toLowerCase();
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
      const probe = await followRedirects(url, { maxHops: 5 });
      return {
        url,
        status: probe.status,
        finalUrl: probe.finalUrl,
        redirects: Math.max(0, probe.hops.length - 1),
        error: probe.error,
      };
    } catch (error) {
      return {
        url,
        status: 0,
        finalUrl: url,
        redirects: 0,
        error: error instanceof Error ? error.message : String(error),
      };
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

/** Read a few sitemap pages for third-party resources; this is not a crawl. */
async function sampleThirdPartyPages(urls: string[]): Promise<ThirdPartyFacts> {
  const candidates = urls.filter(isHtmlUrl).slice(0, 5);
  const sampled = await mapLimit(candidates, 2, async (url) => {
    try {
      const result = await fetchFollowing(url, { timeoutMs: 7000, maxBytes: 64_000 });
      if (result.status !== 200 || !result.body) return null;
      if (!/text\/html|application\/xhtml/i.test(result.contentType)) return null;
      const { document } = parseHTML(result.body);
      const resources = (selector: string, attribute: string) =>
        Array.from(document.querySelectorAll(selector))
          .map((element) => element.getAttribute(attribute) ?? "")
          .filter(Boolean);
      return detectThirdParties({
        url,
        htmlSource: result.body,
        scripts: resources("script[src]", "src"),
        stylesheets: resources('link[rel="stylesheet"][href]', "href"),
        images: resources("img[src]", "src"),
        iframes: resources("iframe[src]", "src"),
        hints: resources('link[rel="preconnect"][href], link[rel="dns-prefetch"][href]', "href"),
      });
    } catch {
      return null;
    }
  });
  return mergeThirdPartyFacts(...sampled.filter((fact): fact is ThirdPartyFacts => fact !== null));
}

function markdownStats(body: string): {
  headings: number;
  links: number;
  title: string;
  description: string;
} {
  let headings = 0;
  let links = 0;
  let title = "";
  let description = "";
  for (const line of body.split(/\r?\n/)) {
    if (/^#{1,6}\s+\S/.test(line)) {
      headings += 1;
      if (!title && /^#\s+/.test(line)) title = line.replace(/^#\s+/, "").trim();
    }
    if (/\]\([^)]+\)/.test(line)) links += 1;
    if (!description && line.trim() && !/^#{1,6}\s+/.test(line) && !/^[-*]\s+/.test(line)) {
      description = line.trim();
    }
  }
  return { headings, links, title, description };
}

function validJson(body: string): boolean {
  try {
    JSON.parse(body);
    return true;
  } catch {
    return false;
  }
}

/** A file is present only when it is a real 2xx response, not a themed 404. */
export function isPresentFile(entry: FileEntryFact | undefined): boolean {
  return Boolean(entry && entry.status >= 200 && entry.status < 300 && !entry.soft404);
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

  const get = (path: string): RawFile | undefined => {
    const raw = byPath.get(path);
    if (!raw || !isPresentFile(raw.entry)) return undefined;
    return raw;
  };
  const ok = (path: string) => isPresentFile(entries[path]);

  const robotsRaw = get("/robots.txt");
  const robots = robotsRaw
    ? parseRobots(robotsRaw.body)
    : { sitemaps: [], blocksAll: false, blockedPaths: [], aiRules: {} };

  // Prefer a sitemap advertised in robots.txt, then the usual candidates.
  const candidates = [...new Set([...robots.sitemaps, new URL("/sitemap.xml", base).href, new URL("/sitemap-index.xml", base).href])];
  const sitemap: SitemapResult & { source: string; contentType: string } = {
    valid: false,
    urls: [],
    lastmod: "",
    source: "",
    contentType: "",
  };

  for (const candidate of candidates) {
    try {
      const response = await fetchFollowing(candidate, { timeoutMs: 8000, maxBytes: 4_000_000 });
      if (response.status !== 200) continue;
      const parsed = parseSitemap(response.body);
      if (!parsed.valid) continue;

      sitemap.valid = true;
      sitemap.source = candidate;
      sitemap.lastmod = parsed.lastmod;
      sitemap.contentType = response.contentType;

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

  // MTA-STS is published under `mta-sts.<registrable-domain>`, not on the
  // homepage host. The policy fetch must not follow redirects.
  const registrable = getDomain(base.hostname) ?? base.hostname;
  let mtaStsRaw: Awaited<ReturnType<typeof fetchText>> | null = null;
  try {
    const response = await fetchText(`https://mta-sts.${registrable}/.well-known/mta-sts.txt`, {
      timeoutMs: 5000,
      maxBytes: 64_000,
      headers: { accept: "text/plain" },
    });
    if (response.status === 200) mtaStsRaw = response;
  } catch {
    // A missing policy host is normal before MTA-STS is configured.
  }
  const mtaStsFields = new Map<string, string>();
  for (const line of (mtaStsRaw?.body ?? "").split(/\r?\n/)) {
    const index = line.indexOf(":");
    if (index > 0) mtaStsFields.set(line.slice(0, index).trim().toLowerCase(), line.slice(index + 1).trim());
  }
  const mtaStsMx = (mtaStsRaw?.body ?? "")
    .split(/\r?\n/)
    .filter((line) => /^mx\s*:/i.test(line))
    .map((line) => line.slice(line.indexOf(":") + 1).trim())
    .filter(Boolean);
  const mtaStsPolicy = {
    present: Boolean(mtaStsRaw),
    valid:
      Boolean(mtaStsRaw) &&
      /^STSv1$/i.test(mtaStsFields.get("version") ?? "") &&
      ["enforce", "testing", "none"].includes((mtaStsFields.get("mode") ?? "").toLowerCase()) &&
      mtaStsMx.length > 0,
    mode: mtaStsFields.get("mode") ?? "",
    maxAge: Number.isFinite(Number(mtaStsFields.get("max_age"))) ? Number(mtaStsFields.get("max_age")) : null,
    mx: mtaStsMx,
  };

  const manifestHref = html?.manifestHref ? new URL(html.manifestHref, base).href : "";
  const manifestRaw = manifestHref
    ? await fetchFollowing(manifestHref, { timeoutMs: 7000, maxBytes: 256_000 }).catch(() => null)
    : get("/manifest.webmanifest") ?? get("/site.webmanifest");
  let manifestInfo: FilesFacts["manifestInfo"] = {
    present: Boolean(manifestHref || manifestRaw),
    valid: false,
    name: "",
    startUrl: "",
    iconCount: 0,
    brokenIcons: [],
  };
  const manifestStatus = manifestRaw
    ? "entry" in manifestRaw
      ? manifestRaw.entry.status
      : manifestRaw.status
    : 0;
  const manifestBody = manifestRaw?.body ?? "";
  const manifestBase =
    manifestHref ||
    (manifestRaw && "entry" in manifestRaw ? fileUrl(manifestRaw.entry.path) : base);
  if (manifestStatus >= 200 && manifestStatus < 300) {
    try {
      const parsed = JSON.parse(manifestBody) as Record<string, unknown>;
      const icons = Array.isArray(parsed.icons) ? (parsed.icons as Record<string, unknown>[]) : [];
      const iconUrls = icons
        .map((icon) => (typeof icon.src === "string" ? new URL(icon.src, manifestBase).href : ""))
        .filter(Boolean)
        .slice(0, 6);
      const statuses = await mapLimit(iconUrls, 3, async (url) => {
        try {
          const probe = await followRedirects(url, { maxHops: 3 });
          return { url, ok: probe.status >= 200 && probe.status < 300 };
        } catch {
          return { url, ok: false };
        }
      });
      manifestInfo = {
        present: true,
        valid:
          typeof parsed.name === "string" &&
          typeof parsed.start_url === "string" &&
          icons.length > 0,
        name: typeof parsed.name === "string" ? parsed.name : "",
        startUrl: typeof parsed.start_url === "string" ? parsed.start_url : "",
        iconCount: icons.length,
        brokenIcons: statuses.filter((item) => !item.ok).map((item) => item.url),
      };
    } catch {
      manifestInfo = { ...manifestInfo, present: true, valid: false };
    }
  }

  const thirdParties = mergeThirdPartyFacts(
    initialThirdParties,
    uniqueUrls.length ? await sampleThirdPartyPages(uniqueUrls) : emptyThirdPartyFacts(),
  );

  const baseHost = new URL(base).hostname;
  const homepage = uniqueUrls.some((url) => {
    try {
      const parsed = new URL(url);
      return parsed.hostname === baseHost && (parsed.pathname === "/" || parsed.pathname === "");
    } catch {
      return false;
    }
  });

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
      sample: uniqueUrls.length ? await sampleUrls(uniqueUrls) : [],
      lastmod: sitemap.lastmod,
      source: sitemap.source,
      contentType: sitemap.contentType,
      homepage,
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
      title: llmsStats.title,
      description: llmsStats.description,
    },
    mtaStsPolicy,
    aiTxt: ok("/ai.txt"),
    changePassword: ok("/.well-known/change-password"),
    aasa: ok("/.well-known/apple-app-site-association") && validJson(get("/.well-known/apple-app-site-association")?.body ?? ""),
    assetlinks: ok("/.well-known/assetlinks.json") && validJson(get("/.well-known/assetlinks.json")?.body ?? ""),
    mtaSts: Boolean(mtaStsRaw),
    gpc: ok("/.well-known/gpc.json") && validJson(get("/.well-known/gpc.json")?.body ?? ""),
    trustTxt: ok("/.well-known/trust.txt"),
    nodeinfo: ok("/.well-known/nodeinfo"),
    webfinger: ok("/.well-known/webfinger"),
    hostMeta: ok("/.well-known/host-meta"),
    humansTxt: ok("/humans.txt"),
    adsTxt: ok("/ads.txt"),
    appAdsTxt: ok("/app-ads.txt"),
    browserconfig: ok("/browserconfig.xml"),
    manifest:
      Boolean(html?.manifestHref) ||
      ok("/manifest.webmanifest") ||
      ok("/site.webmanifest"),
    manifestInfo,
    rootIcons: {
      favicon: ok("/favicon.ico"),
      appleTouch: ok("/apple-touch-icon.png"),
    },
    thirdParties,
  };
}
