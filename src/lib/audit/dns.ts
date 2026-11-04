import type {
  DaneFact,
  DkimKeyFact,
  DmarcExternalReportFact,
  DnsFacts,
  DnsRecords,
  EmailAuthFacts,
  RdapFacts,
} from "./types";

type DohAnswer = { name: string; type: number; TTL: number; data: string };

interface DohResponse {
  Status: number;
  AD?: boolean;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
}

const CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query";
const GOOGLE_DOH = "https://dns.google/resolve";

/** One DNS-over-HTTPS query. Cloudflare first, Google as a fallback. */
export async function dohQuery(
  name: string,
  type: string,
): Promise<{ answers: DohAnswer[]; ad: boolean; status: number }> {
  const params = new URLSearchParams({ name, type });
  const attempts = [
    `${CLOUDFLARE_DOH}?${params.toString()}`,
    `${GOOGLE_DOH}?${params.toString()}`,
  ];

  let lastError: unknown;
  for (const url of attempts) {
    try {
      const response = await fetch(url, {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(6000),
      });
      if (!response.ok) throw new Error(`DNS ${response.status}`);
      const data = (await response.json()) as DohResponse;
      return {
        answers: data.Answer ?? [],
        ad: Boolean(data.AD),
        status: data.Status ?? 0,
      };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("DNS lookup failed");
}

const RECORD_TYPES: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  DS: 43,
  DNSKEY: 48,
  TLSA: 52,
  CAA: 257,
};

async function answersFor(name: string, type: string): Promise<string[]> {
  try {
    const result = await dohQuery(name, type);
    const code = RECORD_TYPES[type.toUpperCase()];
    return result.answers
      .filter((answer) => code === undefined || answer.type === code)
      .map((answer) => answer.data);
  } catch {
    return [];
  }
}

function txtValue(values: string[]): string {
  return values
    .map((value) => value.replace(/^"|"$/g, "").replace(/"\s+"/g, ""))
    .join("");
}

function parseMx(values: string[]): { priority: number; host: string }[] {
  return values
    .map((value) => {
      const match = /^(\d+)\s+(.+?)\.?$/.exec(value.trim());
      return match
        ? { priority: Number(match[1]), host: match[2].replace(/\.$/, "") }
        : null;
    })
    .filter((value): value is { priority: number; host: string } => value !== null)
    .sort((a, b) => a.priority - b.priority);
}

function parseCaa(values: string[]): { flags: number; tag: string; value: string }[] {
  return values
    .map((value) => {
      const match = /^(\d+)\s+(\S+)\s+"?([^"]+)"?$/.exec(value.trim());
      return match
        ? { flags: Number(match[1]), tag: match[2], value: match[3] }
        : null;
    })
    .filter((value): value is { flags: number; tag: string; value: string } => value !== null);
}

function parseSpf(records: string[]): EmailAuthFacts["spf"] {
  const spfRecords = records.filter((value) => /^v=spf1\b/i.test(value.trim()));
  const record = spfRecords[0] ?? "";
  const tokens = record.split(/\s+/).slice(1);
  const all = tokens.find((token) => /^[+\-~?]?all$/i.test(token)) ?? "";
  return {
    present: Boolean(record),
    record,
    records: spfRecords,
    qualifier: all ? all[0] : "",
    // The real count is measured by spfLookupBudget, which follows includes.
    lookupCount: 0,
    voidLookups: 0,
  };
}

function parseDmarc(records: string[]): EmailAuthFacts["dmarc"] {
  const record = records.find((value) => /^v=DMARC1\b/i.test(value.trim())) ?? "";
  const tags = new Map<string, string>();
  for (const part of record.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key && rest.length) tags.set(key.trim().toLowerCase(), rest.join("=").trim());
  }
  return {
    present: Boolean(record),
    record,
    policy: tags.get("p") ?? "",
    subdomainPolicy: tags.get("sp") ?? "",
    nonExistentPolicy: tags.get("np") ?? "",
    testing: (tags.get("t") ?? "").toLowerCase() === "y",
    pct: (tags.get("pct") ?? "").trim() ? Number(tags.get("pct")) : null,
    rua: tags.get("rua") ?? "",
    ruf: tags.get("ruf") ?? "",
    adkim: tags.get("adkim") ?? "",
    aspf: tags.get("aspf") ?? "",
    fo: tags.get("fo") ?? "",
    psd: tags.get("psd") ?? "",
    externalReporting: [],
  };
}

const DKIM_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "selector3",
  "key1",
  "key2",
  "k1",
  "k2",
  "s1",
  "s2",
  "mail",
  "dkim",
  "smtp",
  "mandrill",
  "migadu",
  "mailjet",
  "zoho",
  "mcsv",
  "sendgrid",
  "mailgun",
  "postmark",
  "resend",
  "amazonses",
  "klaviyo",
  "hubspot",
  "mailchimp",
  "everlytickey1",
  "everlytickey2",
  "cm",
  "protonmail",
];

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const clean = value.replace(/\s+/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const clean = value.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(clean.padEnd(Math.ceil(clean.length / 4) * 4, "="));
}

/** RSA modulus size from the DKIM p= value; null when it is not readable. */
async function rsaKeyBits(record: string): Promise<number | null> {
  const p = /(?:^|;)\s*p=([^;]*)/i.exec(record)?.[1]?.trim() ?? "";
  if (!p) return null;
  try {
    const der = base64ToBytes(p);
    const key = await crypto.subtle.importKey(
      "spki",
      der,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["verify"],
    );
    const jwk = (await crypto.subtle.exportKey("jwk", key)) as { n?: string };
    return jwk.n ? base64UrlToBytes(jwk.n).length * 8 : null;
  } catch {
    // Some records are bare PKCS#1 rather than SPKI. Estimate from the length.
    // A malformed p= must not reject the whole DNS phase.
    let length = 0;
    try {
      length = base64ToBytes(p).length;
    } catch {
      return null;
    }
    return length >= 256 ? 2048 : length >= 128 ? 1024 : null;
  }
}

function parseDkimKey(selector: string, record: string): DkimKeyFact {
  const tags = new Map<string, string>();
  for (const part of record.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key && rest.length) tags.set(key.trim().toLowerCase(), rest.join("=").trim());
  }
  return {
    selector,
    record,
    keyType: tags.get("k") ?? "rsa",
    bits: null,
    revoked: !(tags.get("p") ?? "").trim(),
    testing: (tags.get("t") ?? "")
      .split(":")
      .map((value) => value.trim().toLowerCase())
      .includes("y"),
    hashAlgorithms: (tags.get("h") ?? "")
      .split(":")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  };
}

async function detectDkim(
  domain: string,
): Promise<{ selectors: string[]; keys: DkimKeyFact[] }> {
  const found = await Promise.all(
    DKIM_SELECTORS.map(async (selector) => {
      const records = await answersFor(`${selector}._domainkey.${domain}`, "TXT");
      const record = txtValue(records);
      return /v=DKIM1/i.test(record) || /(?:^|;)\s*p=/.test(record)
        ? parseDkimKey(selector, record)
        : null;
    }),
  );
  const keys = found.filter((key): key is DkimKeyFact => key !== null);
  // A wildcard *.example.com TXT makes every selector resolve to the same
  // record; keep one entry per distinct record so a null key is not counted 30
  // times.
  const unique = new Map<string, DkimKeyFact>();
  for (const key of keys) {
    if (!unique.has(key.record)) unique.set(key.record, key);
  }
  const uniqueKeys = [...unique.values()];
  await Promise.all(
    uniqueKeys.map(async (key) => {
      if (key.keyType.toLowerCase() === "rsa") key.bits = await rsaKeyBits(key.record);
    }),
  );
  uniqueKeys.sort((a, b) => a.selector.localeCompare(b.selector));
  return {
    selectors: uniqueKeys.filter((key) => !key.revoked).map((key) => key.selector),
    keys: uniqueKeys,
  };
}

interface SpfMechanism {
  kind: "include" | "redirect" | "lookup";
  value: string;
}

function spfMechanisms(record: string): SpfMechanism[] {
  const mechanisms: SpfMechanism[] = [];
  for (const token of record.split(/\s+/).slice(1)) {
    const bare = token.replace(/^[+\-~?]/, "");
    if (/^include:/i.test(bare)) mechanisms.push({ kind: "include", value: bare.slice(8) });
    else if (/^redirect=/i.test(bare)) mechanisms.push({ kind: "redirect", value: bare.slice(9) });
    else if (/^exists:/i.test(bare)) mechanisms.push({ kind: "lookup", value: bare.slice(7) });
    else if (/^a(:|$)/i.test(bare)) mechanisms.push({ kind: "lookup", value: bare.slice(2) });
    else if (/^mx(:|$)/i.test(bare)) mechanisms.push({ kind: "lookup", value: bare.slice(3) });
    else if (/^ptr(:|$)/i.test(bare)) mechanisms.push({ kind: "lookup", value: bare.slice(4) });
    // exp= is not a mechanism and does not count towards the ten-lookup limit.
  }
  // RFC 7208 ignores redirect= when an all mechanism is present.
  const hasAll = record.split(/\s+/).some((token) => /^[+\-~?]?all$/i.test(token));
  return hasAll ? mechanisms.filter((mechanism) => mechanism.kind !== "redirect") : mechanisms;
}

/**
 * Count the DNS lookups an SPF record costs, following include: and redirect=
 * up to ten levels. RFC 7208's limit is ten. `mx` counts as one term here, so a
 * record with several MX hosts can cost more than this estimate.
 */
async function spfLookupBudget(
  domain: string,
  rootRecord: string,
): Promise<{ total: number; voidLookups: number }> {
  let total = 0;
  let voidLookups = 0;
  const seen = new Set([domain]);
  let frontier: { domain: string; record: string }[] = [{ domain, record: rootRecord }];

  for (let depth = 0; depth < 10 && frontier.length; depth += 1) {
    const targets: string[] = [];
    for (const item of frontier) {
      for (const mechanism of spfMechanisms(item.record)) {
        total += 1;
        if (mechanism.kind === "lookup") continue;
        const target = mechanism.value
          .replace(/^\*\./, "")
          .replace(/\/.*$/, "")
          .toLowerCase();
        if (!target || target.includes("%") || seen.has(target)) continue;
        seen.add(target);
        targets.push(target);
      }
    }

    const fetched = await Promise.all(
      targets.map(async (target) => ({
        target,
        records: await answersFor(target, "TXT"),
      })),
    );
    const next: { domain: string; record: string }[] = [];
    for (const entry of fetched) {
      const record = entry.records
        .map((value) => txtValue([value]))
        .find((value) => /^v=spf1\b/i.test(value));
      if (record) next.push({ domain: entry.target, record });
      else voidLookups += 1;
    }
    frontier = next;
  }

  return { total, voidLookups };
}

function tagValue(record: string, tag: string): string {
  return new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;]*)`, "i").exec(record)?.[1]?.trim() ?? "";
}

async function externalDmarcReporting(
  domain: string,
  rua: string,
  ruf: string,
): Promise<DmarcExternalReportFact[]> {
  const targets = [
    ...new Set(
      [rua, ruf]
        .join(",")
        .split(",")
        .map((value) => value.trim())
        .filter((value) => /^mailto:/i.test(value))
        .map((value) => value.replace(/^mailto:/i, "").split("@")[1]?.toLowerCase() ?? "")
        .filter(Boolean),
    ),
  ].filter((target) => target !== domain && target !== `www.${domain}`);

  return Promise.all(
    targets.slice(0, 5).map(async (target) => {
      const records = await answersFor(`${domain}._report._dmarc.${target}`, "TXT");
      const record = records.map((value) => txtValue([value])).join(" ");
      return { target, authorized: /v=DMARC1/i.test(record), record };
    }),
  );
}

async function collectDane(mx: { priority: number; host: string }[]): Promise<DaneFact[]> {
  const hosts = mx
    .map((item) => item.host)
    .filter((host) => host && host !== ".")
    .slice(0, 3);
  return Promise.all(
    hosts.map(async (host) => ({
      host,
      records: await answersFor(`_25._tcp.${host}`, "TLSA"),
    })),
  );
}

function vcardName(entity: Record<string, unknown>): string {
  const vcard = entity.vcardArray as unknown;
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return "";
  const properties = vcard[1] as unknown[];
  for (const property of properties) {
    if (Array.isArray(property) && property[0] === "fn" && typeof property[3] === "string") {
      return property[3];
    }
  }
  return "";
}

async function collectRdap(domain: string): Promise<RdapFacts | null> {
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { accept: "application/rdap+json" },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return null;
    const data = (await response.json()) as Record<string, unknown>;

    const events = Array.isArray(data.events) ? (data.events as Record<string, unknown>[]) : [];
    const eventDate = (action: string) => {
      const event = events.find((item) => item.eventAction === action);
      return typeof event?.eventDate === "string" ? event.eventDate : "";
    };

    const entities = Array.isArray(data.entities)
      ? (data.entities as Record<string, unknown>[])
      : [];
    const registrarEntity = entities.find((entity) =>
      Array.isArray(entity.roles) && (entity.roles as string[]).includes("registrar"),
    );
    const registrar = registrarEntity ? vcardName(registrarEntity) : "";

    const nameservers = Array.isArray(data.nameservers)
      ? (data.nameservers as Record<string, unknown>[])
          .map((item) => (typeof item.ldhName === "string" ? item.ldhName : ""))
          .filter(Boolean)
      : [];

    const secureDns = data.secureDNS as Record<string, unknown> | undefined;

    return {
      registrar,
      registered: eventDate("registration"),
      expires: eventDate("expiration"),
      updated: eventDate("last changed"),
      statuses: Array.isArray(data.status) ? (data.status as string[]) : [],
      nameservers,
      secureDns: Boolean(secureDns?.delegationSigned),
    };
  } catch {
    return null;
  }
}

/** Collect DNS records, email authentication and registration data. */
export async function collectDns(domain: string): Promise<DnsFacts> {
  const [a, aaaa, cname, ns, mx, txt, caa, dnskey, ds, soa, dmarcTxt, bimiTxt, mtaStsTxt, tlsRptTxt, rdap, dkim] =
    await Promise.all([
      answersFor(domain, "A"),
      answersFor(domain, "AAAA"),
      answersFor(domain, "CNAME"),
      answersFor(domain, "NS"),
      answersFor(domain, "MX"),
      answersFor(domain, "TXT"),
      answersFor(domain, "CAA"),
      answersFor(domain, "DNSKEY"),
      answersFor(domain, "DS"),
      answersFor(domain, "SOA"),
      answersFor(`_dmarc.${domain}`, "TXT"),
      answersFor(`default._bimi.${domain}`, "TXT"),
      answersFor(`_mta-sts.${domain}`, "TXT"),
      answersFor(`_smtp._tls.${domain}`, "TXT"),
      collectRdap(domain),
      detectDkim(domain),
    ]);

  const txtRecords = txt.map((value) => txtValue([value]));
  const mxRecords = parseMx(mx);
  const records: DnsRecords = {
    a,
    aaaa,
    cname,
    ns,
    mx: mxRecords,
    txt: txtRecords,
    caa: parseCaa(caa),
    dnskey: dnskey.length > 0,
    ds: ds.length > 0,
    ad: false,
    soa: soa[0] ?? "",
  };

  const spf = parseSpf(txtRecords);
  const dmarc = parseDmarc(dmarcTxt.map((value) => txtValue([value])));
  const bimiRecord = txtValue(bimiTxt);
  const mtaStsRecord = txtValue(mtaStsTxt);
  const tlsRptRecord = txtValue(tlsRptTxt);

  // The AD bit is per query; ask once more for a signed signal. The SPF budget,
  // TLSA records and any external DMARC authorisation run alongside it.
  const [adQuery, spfBudget, dane, externalReporting] = await Promise.all([
    dohQuery(domain, "DS").catch(() => null),
    spf.present
      ? spfLookupBudget(domain, spf.record)
      : Promise.resolve({ total: 0, voidLookups: 0 }),
    collectDane(mxRecords),
    dmarc.present && (dmarc.rua || dmarc.ruf)
      ? externalDmarcReporting(domain, dmarc.rua, dmarc.ruf)
      : Promise.resolve([]),
  ]);
  records.ad = Boolean(adQuery?.ad);
  spf.lookupCount = spfBudget.total;
  spf.voidLookups = spfBudget.voidLookups;
  dmarc.externalReporting = externalReporting;

  const email: EmailAuthFacts = {
    spf,
    dmarc,
    dkimSelectors: dkim.selectors,
    dkimKeys: dkim.keys,
    bimi: /v=BIMI1/i.test(bimiRecord),
    bimiLogo: tagValue(bimiRecord, "l"),
    bimiAuthority: tagValue(bimiRecord, "a"),
    mtaSts: /v=STSv1/i.test(mtaStsRecord),
    mtaStsId: tagValue(mtaStsRecord, "id"),
    tlsRpt: /v=TLSRPTv1/i.test(tlsRptRecord),
    tlsRptRua: tagValue(tlsRptRecord, "rua"),
    dane,
  };

  return {
    records,
    email,
    rdap,
    resolved: a.length > 0 || aaaa.length > 0 || cname.length > 0,
  };
}
