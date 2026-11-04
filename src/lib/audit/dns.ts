import type {
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

async function answersFor(name: string, type: string): Promise<string[]> {
  try {
    const result = await dohQuery(name, type);
    return result.answers.map((answer) => answer.data);
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
  const record = records.find((value) => /^v=spf1\b/i.test(value.trim())) ?? "";
  const tokens = record.split(/\s+/).slice(1);
  const lookupCount = tokens.filter((token) =>
    /^(include:|a$|a:|mx$|mx:|ptr$|ptr:|exists:|redirect=|exp=)/i.test(token),
  ).length;
  const all = tokens.find((token) => /^[+\-~?]?all$/i.test(token)) ?? "";
  return {
    present: Boolean(record),
    record,
    qualifier: all ? all[0] : "",
    lookupCount,
    voidLookups: 0,
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
    // exp= is a modifier, not a mechanism, and does not count towards the limit.
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
    pct: tags.has("pct") ? Number(tags.get("pct")) : null,
    rua: tags.get("rua") ?? "",
    ruf: tags.get("ruf") ?? "",
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

async function detectDkim(domain: string): Promise<string[]> {
  const found: string[] = [];
  await Promise.all(
    DKIM_SELECTORS.map(async (selector) => {
      const records = await answersFor(`${selector}._domainkey.${domain}`, "TXT");
      const joined = txtValue(records);
      if (/v=DKIM1/i.test(joined) || /(?:^|;)\s*p=/.test(joined)) {
        found.push(selector);
      }
    }),
  );
  return found.sort();
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
  const [a, aaaa, cname, ns, mx, txt, caa, dnskey, ds, soa, dmarcTxt, bimiTxt, mtaStsTxt, tlsRptTxt, rdap, dkimSelectors] =
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
  const spf = parseSpf(txtRecords);
  // parseSpf gives a flat count; follow includes and redirects for the limit.
  const spfBudget = spf.present
    ? await spfLookupBudget(domain, spf.record)
    : { total: 0, voidLookups: 0 };
  spf.lookupCount = spfBudget.total;
  spf.voidLookups = spfBudget.voidLookups;
  const records: DnsRecords = {
    a,
    aaaa,
    cname,
    ns,
    mx: parseMx(mx),
    txt: txtRecords,
    caa: parseCaa(caa),
    dnskey: dnskey.length > 0,
    ds: ds.length > 0,
    ad: false,
    soa: soa[0] ?? "",
  };

  // The AD bit is per query; ask once more for a signed signal.
  try {
    const signed = await dohQuery(domain, "DS");
    records.ad = signed.ad;
  } catch {
    // Ignore — DNSKEY/DS presence still tells us the zone is signed.
  }

  const email: EmailAuthFacts = {
    spfRecords: txtRecords.filter((value) => /^v=spf1\b/i.test(value.trim())),
    spf,
    dmarc: parseDmarc(dmarcTxt.map((value) => txtValue([value]))),
    dkimSelectors,
    bimi: bimiTxt.map((value) => txtValue([value])).some((value) => /v=BIMI1/i.test(value)),
    mtaSts: mtaStsTxt.map((value) => txtValue([value])).some((value) => /v=STSv1/i.test(value)),
    tlsRpt: tlsRptTxt.map((value) => txtValue([value])).some((value) => /v=TLSRPTv1/i.test(value)),
  };

  return {
    records,
    email,
    rdap,
    resolved: a.length > 0 || aaaa.length > 0 || cname.length > 0,
  };
}
