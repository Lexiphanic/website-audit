import ipaddr from "ipaddr.js";
import { dohQuery } from "./dns";

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata",
  "metadata.google.internal",
  "instance-data",
  "instance-data.ec2.internal",
  "kubernetes.default",
  "kubernetes.default.svc",
]);

const BLOCKED_SUFFIXES = [
  ".local",
  ".localdomain",
  ".internal",
  ".home.arpa",
  ".localhost",
  ".test",
  ".invalid",
  ".onion",
];

export function isIpLiteral(value: string): boolean {
  return ipaddr.isValid(value.replace(/^\[|\]$/g, ""));
}

/** True for any address that is not ordinary public unicast. */
export function isPrivateAddress(value: string): boolean {
  const bare = value.replace(/^\[|\]$/g, "").split("%")[0];
  if (!ipaddr.isValid(bare)) return true;
  let address = ipaddr.parse(bare);
  if (address.kind() === "ipv6") {
    const v6 = address as ipaddr.IPv6;
    if (v6.isIPv4MappedAddress()) {
      address = v6.toIPv4Address();
    }
  }
  return address.range() !== "unicast";
}

export function isBlockedHostname(hostname: string): boolean {
  const host = hostname.replace(/\.$/, "").toLowerCase();
  if (BLOCKED_HOSTS.has(host)) return true;
  if (!host.includes(".")) return true;
  return BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

/** Resolve a hostname through DoH and return every address it points at. */
export async function resolveHost(hostname: string): Promise<string[]> {
  const host = hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  const [a, aaaa, cname] = await Promise.all([
    dohQuery(host, "A").catch(() => null),
    dohQuery(host, "AAAA").catch(() => null),
    dohQuery(host, "CNAME").catch(() => null),
  ]);

  const addresses = new Set<string>();
  for (const answer of a?.answers ?? []) addresses.add(answer.data.replace(/\.$/, ""));
  for (const answer of aaaa?.answers ?? []) addresses.add(answer.data.replace(/\.$/, ""));

  // If the name is a CNAME, follow the target once. DoH normally includes the
  // final A/AAAA answers too, but not every resolver does.
  const alias = cname?.answers[0]?.data?.replace(/\.$/, "");
  if (alias && alias !== host) {
    const [aliasA, aliasAaaa] = await Promise.all([
      dohQuery(alias, "A").catch(() => null),
      dohQuery(alias, "AAAA").catch(() => null),
    ]);
    for (const answer of aliasA?.answers ?? []) addresses.add(answer.data.replace(/\.$/, ""));
    for (const answer of aliasAaaa?.answers ?? []) addresses.add(answer.data.replace(/\.$/, ""));
  }

  return [...addresses];
}

/**
 * Validate a URL before any outbound request. This is the single place that
 * decides whether a public scan may touch a host: no credentials, no unusual
 * ports, no IP literals, no private ranges, no metadata services.
 */
export async function assertSafeUrl(value: string): Promise<{ url: URL; addresses: string[] }> {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Enter a valid website address.");
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
  if (isBlockedHostname(host)) {
    throw new Error("That host is not a public website.");
  }

  if (isIpLiteral(host)) {
    if (isPrivateAddress(host)) {
      throw new Error("Private and reserved addresses cannot be audited.");
    }
    return { url, addresses: [host] };
  }

  const addresses = await resolveHost(host);
  if (!addresses.length) {
    throw new Error(`We could not resolve ${host}. Check the spelling and try again.`);
  }
  if (addresses.some(isPrivateAddress)) {
    throw new Error("That host resolves to a private or reserved address, so it cannot be audited.");
  }

  return { url, addresses };
}
