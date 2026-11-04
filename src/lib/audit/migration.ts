import { detectDnsProvider, detectEdge } from "./third-parties";
import type {
  DnsFacts,
  FilesFacts,
  HtmlFacts,
  MigrationFacts,
  SecurityFacts,
  TransportFacts,
} from "./types";

function hosting(headers: Record<string, string>, dns: DnsFacts): string {
  const edge = detectEdge(headers)?.name;
  if (edge) return edge;
  const server = (headers.server ?? "").toLowerCase();
  // S3 is hosting, not an edge, so it does not belong in detectEdge.
  if (server.includes("amazons3")) return "Amazon S3";
  const provider = detectDnsProvider(dns.records.ns)?.name;
  if (provider) return provider;
  return server ? `Unknown (${server})` : "Unknown";
}

function analyticsFrom(files: FilesFacts, html: HtmlFacts): string[] {
  const tracked = new Set(
    files.thirdParties.providers
      .filter((provider) =>
        ["advertising", "analytics", "tag-manager", "session-replay"].includes(provider.category),
      )
      .map((provider) => provider.name),
  );
  // Fall back to the homepage regexes when the richer detector found nothing.
  return tracked.size ? [...tracked] : html.analytics;
}

function emailProvider(dns: DnsFacts): string {
  const hosts = dns.records.mx.map((record) => record.host.toLowerCase()).join(" ");
  if (!hosts) return "No MX records";
  if (hosts.includes("google") || hosts.includes("gmail")) return "Google Workspace";
  if (hosts.includes("outlook") || hosts.includes("microsoft")) return "Microsoft 365";
  if (hosts.includes("zoho")) return "Zoho Mail";
  if (hosts.includes("proton")) return "Proton Mail";
  if (hosts.includes("fastmail")) return "Fastmail";
  if (hosts.includes("mimecast")) return "Mimecast";
  if (hosts.includes("barracuda")) return "Barracuda";
  return dns.records.mx[0]?.host ?? "Unknown";
}

function ecommerce(html: HtmlFacts): string[] {
  const found = new Set<string>();
  const haystack = html.links.map((link) => link.href).join(" ").toLowerCase();
  if (/\/cart|\/checkout|\/basket/.test(haystack)) found.add("Cart / checkout flow");
  if (/\/product|\/products|\/shop/.test(haystack)) found.add("Product catalogue");
  if (html.platform === "Shopify") found.add("Shopify");
  if (html.platform === "WooCommerce" || /woocommerce/.test(haystack)) found.add("WooCommerce");
  return [...found];
}

function booking(html: HtmlFacts): string[] {
  const found = new Set<string>();
  const haystack = html.links.map((link) => link.href).join(" ").toLowerCase();
  if (/calendly\.com/.test(haystack)) found.add("Calendly");
  if (/acuityscheduling\.com/.test(haystack)) found.add("Acuity Scheduling");
  if (/booksy\.com/.test(haystack)) found.add("Booksy");
  if (/simplybook\.me/.test(haystack)) found.add("SimplyBook.me");
  if (/\/book|\/booking|\/reservations?/.test(haystack)) found.add("On-site booking flow");
  return [...found];
}

function legacy(html: HtmlFacts, htmlSource: string): string[] {
  const found = new Set<string>();
  const jquery = /jquery[/-]?(\d+\.\d+(?:\.\d+)?)/i.exec(htmlSource);
  if (jquery) found.add(`jQuery ${jquery[1]}`);
  if (/\.swf|shockwave|flash/i.test(htmlSource)) found.add("Flash / Shockwave");
  if (html.mixedContent.length) found.add("HTTP assets on an HTTPS page");
  if (/<font\b|<center\b|<marquee\b|<blink\b/i.test(htmlSource)) found.add("Deprecated HTML");
  if (/jquery-migrate/i.test(htmlSource)) found.add("jQuery Migrate");
  return [...found];
}

/** What the site is, what it carries, and what moving it would involve. */
export async function collectMigration(
  dns: DnsFacts,
  transport: TransportFacts,
  html: HtmlFacts,
  files: FilesFacts,
  security: SecurityFacts,
): Promise<MigrationFacts> {
  const rdap = dns.rdap;
  const languages = new Set<string>();
  if (html.lang) languages.add(html.lang);
  for (const item of html.hreflang) {
    if (item.lang && item.lang !== "x-default") languages.add(item.lang);
  }

  const legalPages = [
    security.legal.privacy ? "Privacy notice" : "",
    security.legal.terms ? "Terms" : "",
    security.legal.cookies ? "Cookie notice" : "",
    security.legal.accessibility ? "Accessibility statement" : "",
  ].filter(Boolean);

  const redirectComplexity = Math.max(...transport.probes.map((probe) => probe.hops.length), 0);

  return {
    platform: html.platform,
    platformConfidence: html.platformConfidence,
    hosting: hosting(transport.homepage.headers, dns),
    pageCount: files.sitemaps.count,
    ecommerce: ecommerce(html),
    booking: booking(html),
    analytics: analyticsFrom(files, html),
    emailProvider: emailProvider(dns),
    registrar: rdap?.registrar ?? "Unknown",
    domainExpires: rdap?.expires ?? "",
    transferLocked: rdap ? rdap.statuses.some((status) => /clientTransferProhibited/i.test(status)) : null,
    dnsSummary: {
      a: dns.records.a.length,
      aaaa: dns.records.aaaa.length,
      mx: dns.records.mx.length,
      ns: dns.records.ns.length,
      caa: dns.records.caa.length,
      txt: dns.records.txt.length,
    },
    emails: html.emails,
    phones: html.phones,
    social: html.social,
    legalPages,
    legacy: legacy(html, htmlSourceFallback(html)),
    languages: [...languages],
    redirectComplexity,
    content: {
      words: html.wordCount,
      images: html.images.length,
      pages: files.sitemaps.count,
    },
  };
}

/**
 * The raw HTML is not stored on HtmlFacts (it can be large). The legacy check
 * uses what we have; the workflow can pass a short source sample if needed.
 */
function htmlSourceFallback(html: HtmlFacts): string {
  return [
    html.generator,
    ...html.scripts.map((script) => script.src),
    ...html.stylesheets,
    ...html.links.slice(0, 100).map((link) => link.href),
    ...html.mixedContent,
  ].join("\n");
}
