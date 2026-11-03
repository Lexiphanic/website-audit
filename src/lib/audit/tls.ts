import type { CertificateInfo, TlsProbe, TlsVersionProbe } from "./types";

const SSLLABS = "https://api.ssllabs.com/api/v3/analyze";
const CRTSH = "https://crt.sh/";

interface LabProtocol {
  name?: string;
  version?: string;
}

interface LabCert {
  subject?: string;
  issuerSubject?: string;
  notBefore?: number;
  notAfter?: number;
  altNames?: string | string[];
  serialNumber?: string;
  sha256Hash?: string;
  keyAlg?: string;
  keySize?: number;
}

interface LabEndpoint {
  ipAddress?: string;
  grade?: string;
  statusMessage?: string;
  details?: {
    protocols?: LabProtocol[];
    cert?: LabCert;
    certChains?: { certIds?: string[] }[];
    chain?: { certs?: LabCert[] };
    supportsAlpn?: boolean;
    alpnProtocols?: string[] | string;
  };
}

interface LabResponse {
  host?: string;
  status?: string;
  grade?: string;
  endpoints?: LabEndpoint[];
  certs?: LabCert[];
  errors?: { message?: string }[];
}

interface CrtEntry {
  issuer_name?: string;
  common_name?: string;
  name_value?: string;
  not_before?: string;
  not_after?: string;
  serial_number?: string;
}

export interface LabsSummary {
  state: "ready" | "pending" | "error";
  grade: string;
  certificate: CertificateInfo | null;
  versions: Record<string, TlsVersionProbe>;
  cipher: string;
  protocol: string;
  http2: boolean;
  error?: string;
}

function issuerName(value: string): string {
  const cn = /CN=([^,]+)/i.exec(value)?.[1]?.trim();
  const o = /(?:^|,)\s*O=([^,]+)/i.exec(value)?.[1]?.trim();
  return o || cn || value;
}

function subjectName(value: string): string {
  return /CN=([^,]+)/i.exec(value)?.[1]?.trim() ?? value;
}

function certFromCrt(entry: CrtEntry, daysRemaining: number): CertificateInfo {
  const names = (entry.name_value ?? entry.common_name ?? "")
    .split(/\r?\n/)
    .map((name) => name.trim().toLowerCase())
    .filter(Boolean);
  const issuer = entry.issuer_name ?? "";
  return {
    subject: entry.common_name ?? subjectName(issuer),
    issuer,
    issuerOrganisation: issuerName(issuer),
    validFrom: entry.not_before ?? "",
    validTo: entry.not_after ?? "",
    daysRemaining,
    sans: [...new Set(names)],
    serial: entry.serial_number ?? "",
    fingerprint: "",
    chainLength: 1,
    authorized: daysRemaining > 0,
    authorizationError: daysRemaining > 0 ? "" : "Certificate has expired",
  };
}

function certFromLab(cert: LabCert): CertificateInfo {
  const notAfter = typeof cert.notAfter === "number" ? new Date(cert.notAfter) : new Date(0);
  const daysRemaining = Math.round((notAfter.valueOf() - Date.now()) / 86_400_000);
  const altNames = Array.isArray(cert.altNames)
    ? cert.altNames
    : (cert.altNames ?? "").split(/,\s*/);
  return {
    subject: subjectName(cert.subject ?? ""),
    issuer: cert.issuerSubject ?? "",
    issuerOrganisation: issuerName(cert.issuerSubject ?? ""),
    validFrom: typeof cert.notBefore === "number" ? new Date(cert.notBefore).toISOString() : "",
    validTo: notAfter.toISOString(),
    daysRemaining,
    sans: altNames.map((name) => String(name).replace(/^DNS:/i, "").trim().toLowerCase()).filter(Boolean),
    serial: cert.serialNumber ?? "",
    fingerprint: cert.sha256Hash ?? "",
    chainLength: 1,
    authorized: daysRemaining > 0,
    authorizationError: daysRemaining > 0 ? "" : "Certificate has expired",
  };
}

/** Latest certificate from Certificate Transparency, used as a fast fallback. */
export async function certificateFromCrt(domain: string): Promise<CertificateInfo | null> {
  try {
    const url = `${CRTSH}?q=${encodeURIComponent(domain)}&output=json&exclude=expired`;
    const response = await fetch(url, { signal: AbortSignal.timeout(12_000) });
    if (!response.ok) return null;
    const entries = (await response.json()) as CrtEntry[];
    if (!Array.isArray(entries) || !entries.length) return null;

    entries.sort((a, b) => String(b.not_before ?? "").localeCompare(String(a.not_before ?? "")));
    const latest = entries[0];
    const notAfter = latest.not_after ? new Date(latest.not_after).valueOf() : 0;
    const daysRemaining = notAfter ? Math.round((notAfter - Date.now()) / 86_400_000) : 0;
    return certFromCrt(latest, daysRemaining);
  } catch {
    return null;
  }
}

function emptyLabs(state: "error" | "pending", error?: string): LabsSummary {
  return {
    state,
    grade: "",
    certificate: null,
    versions: {},
    cipher: "",
    protocol: "",
    http2: false,
    error,
  };
}

function parseLab(data: LabResponse): LabsSummary {
  if (data.status === "ERROR") {
    return emptyLabs("error", data.errors?.[0]?.message ?? "SSL Labs could not scan the host");
  }

  const endpoint =
    data.endpoints?.find((item) => item.statusMessage === "Ready" && item.details) ??
    data.endpoints?.find((item) => item.details) ??
    data.endpoints?.[0];

  if (data.status !== "READY" && !endpoint?.details) {
    return emptyLabs("pending");
  }

  const details = endpoint?.details;
  const protocols = details?.protocols ?? [];
  const has = (version: string) => protocols.some((item) => item.version === version);
  const versions: Record<string, TlsVersionProbe> = {
    tls12: { supported: has("1.2"), protocol: "TLS 1.2", cipher: "" },
    tls13: { supported: has("1.3"), protocol: "TLS 1.3", cipher: "" },
    legacy: { supported: has("1.0") || has("1.1"), protocol: "TLS 1.0/1.1", cipher: "" },
  };

  const leaf = data.certs?.[0] ?? details?.cert;
  const certificate = leaf
    ? {
        ...certFromLab(leaf),
        chainLength: details?.certChains?.[0]?.certIds?.length ?? (data.certs?.length ?? 1),
      }
    : null;

  const alpn = Array.isArray(details?.alpnProtocols)
    ? details.alpnProtocols
    : [details?.alpnProtocols ?? ""];

  return {
    state: "ready",
    grade: endpoint?.grade ?? data.grade ?? "",
    certificate,
    versions,
    cipher: "",
    protocol: protocols.map((item) => `${item.name ?? "TLS"} ${item.version ?? ""}`.trim()).join(", "),
    http2: Boolean(details?.supportsAlpn && alpn.some((value) => value.includes("h2"))),
  };
}

async function queryLabs(host: string): Promise<LabsSummary> {
  try {
    const params = new URLSearchParams({
      host,
      all: "done",
      fromCache: "on",
      maxAge: "24",
    });
    const response = await fetch(`${SSLLABS}?${params.toString()}`, {
      signal: AbortSignal.timeout(20_000),
    });
    if (response.status === 429) {
      return emptyLabs("error", "SSL Labs rate limit reached; try again later");
    }
    if (!response.ok) {
      return emptyLabs("error", `SSL Labs returned ${response.status}`);
    }
    return parseLab((await response.json()) as LabResponse);
  } catch (error) {
    return emptyLabs("error", error instanceof Error ? error.message : String(error));
  }
}

/** Submit (or read the cache for) an SSL Labs scan. Never blocks on a new scan. */
export async function startLabs(host: string): Promise<LabsSummary> {
  return queryLabs(host);
}

/** Poll an in-progress SSL Labs scan. */
export async function pollLabs(host: string): Promise<LabsSummary> {
  return queryLabs(host);
}

export function emptyTlsProbe(error: string): TlsProbe {
  return {
    certificate: null,
    protocol: "",
    cipher: "",
    alpn: "",
    versions: {},
    grade: "",
    source: "",
    pending: false,
    error,
  };
}

export function tlsFromLabs(summary: LabsSummary, fallback: CertificateInfo | null): TlsProbe {
  return {
    certificate: summary.certificate ?? fallback,
    protocol: summary.protocol,
    cipher: summary.cipher,
    alpn: "",
    versions: summary.versions,
    grade: summary.grade,
    source: summary.certificate ? "SSL Labs" : fallback ? "crt.sh" : "",
    pending: summary.state === "pending",
    error: summary.error,
  };
}
