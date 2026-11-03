import { parse as parseDomain } from "tldts";
import { isIpLiteral, isBlockedHostname } from "./ssrf";

export interface NormalizedTarget {
  /** Registrable domain, used for the report key and apex/www checks. */
  domain: string;
  /** Hostname the visitor entered, without www. */
  host: string;
  /** Normalised https origin for the registrable domain. */
  origin: string;
  /** The URL the visitor typed, cleaned up. */
  inputUrl: string;
}

export function normalizeTarget(input: string): NormalizedTarget {
  const raw = input.trim();
  if (!raw) throw new Error("Enter a website address.");

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw)
    ? raw
    : raw.startsWith("//")
      ? `https:${raw}`
      : `https://${raw}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error("Enter a valid website address, such as example.com.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http:// and https:// addresses can be audited.");
  }
  if (url.username || url.password) {
    throw new Error("Addresses containing a username or password cannot be audited.");
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new Error("Only the standard web ports (80 and 443) can be audited.");
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!host) throw new Error("Enter a website address.");
  if (isIpLiteral(host)) throw new Error("Enter a domain name, not an IP address.");
  if (isBlockedHostname(host)) throw new Error("That host is not a public website.");

  const parsed = parseDomain(host);
  if (!parsed.domain) {
    throw new Error("Enter a full domain name, such as example.com.");
  }

  const domain = parsed.domain.toLowerCase();
  const hostWithoutWww = host.startsWith("www.") ? host.slice(4) : host;

  return {
    domain,
    host: hostWithoutWww,
    origin: `https://${domain}`,
    inputUrl: `${url.protocol}//${url.host}${url.pathname === "/" ? "" : url.pathname}`,
  };
}

/** Parse the :domain route parameter, which is always the registrable domain. */
export function domainFromParam(value: string): string {
  const decoded = decodeURIComponent(value).trim().toLowerCase();
  const parsed = parseDomain(decoded);
  if (!parsed.domain) throw new Error("Invalid domain");
  return parsed.domain.toLowerCase();
}

export function reportPath(domain: string): string {
  return `/reports/${domain}`;
}
