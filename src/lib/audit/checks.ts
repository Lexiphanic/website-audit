import type {
  AuditFacts,
  CheckResult,
  CheckStatus,
} from "./types";

const pass = (key: string, observed: string, evidence?: string): CheckResult => ({
  key,
  status: "pass",
  observed,
  evidence,
});
const warn = (key: string, observed: string, evidence?: string): CheckResult => ({
  key,
  status: "warn",
  observed,
  evidence,
});
const fail = (key: string, observed: string, evidence?: string): CheckResult => ({
  key,
  status: "fail",
  observed,
  evidence,
});
const info = (key: string, observed: string, evidence?: string): CheckResult => ({
  key,
  status: "info",
  observed,
  evidence,
});
const skip = (key: string, observed = "Not checked"): CheckResult => ({
  key,
  status: "skipped",
  observed,
});

function hostOf(value: string): string {
  try {
    return new URL(value).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

function certDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? value
    : date.toLocaleDateString("en-GB", { dateStyle: "long" });
}

function statusOk(status: number): boolean {
  return status >= 200 && status < 400;
}

/** CA/Browser Forum maximum certificate lifetime for the issuance date. */
function certLifetimeLimit(issuedAt: number): number {
  if (!issuedAt) return 398;
  if (issuedAt >= Date.UTC(2029, 2, 15)) return 47;
  if (issuedAt >= Date.UTC(2027, 2, 15)) return 100;
  if (issuedAt >= Date.UTC(2026, 2, 15)) return 200;
  return 398;
}

function ms(value: string): number | null {
  const match = /([\d.]+)\s*(ms|s)?/i.exec(value ?? "");
  if (!match) return null;
  const number = Number(match[1]);
  if (!Number.isFinite(number)) return null;
  return match[2]?.toLowerCase() === "s" ? number * 1000 : number;
}

function cwvCheck(key: string, value: string, good: number, poor: number): CheckResult {
  const numeric = ms(value);
  if (numeric === null) return skip(key, "Not measured");
  if (numeric <= good) return pass(key, value);
  if (numeric <= poor) return warn(key, value);
  return fail(key, value);
}

/* ------------------------------------------------------------------ */
/* Transport                                                          */
/* ------------------------------------------------------------------ */

export function transportChecks(facts: AuditFacts): CheckResult[] {
  const t = facts.transport;
  if (!t) {
    return [
      "https-apex", "https-www", "http-https-apex", "http-https-www",
      "cert-apex", "cert-www", "cert-validity", "cert-chain", "cert-hostname",
      "tls12", "tls13", "tls-legacy", "hsts-apex", "hsts-www", "hsts-max-age",
      "hsts-subdomains", "hsts-preload", "hsts-preload-list", "ipv6",
      "http2", "http3", "mixed-content", "ocsp-stapling", "certificate-transparency",
      "cipher-strength", "cert-lifetime", "cert-key-size", "forward-secrecy",
    ].map((key) => skip(key, "Transport checks could not run"));
  }

  const httpsApex = t.probes[1];
  const httpsWww = t.probes[3];
  const httpApex = t.probes[0];
  const httpWww = t.probes[2];
  const cert = t.tls.apex?.certificate ?? null;
  const certWww = t.tls.www?.certificate ?? null;
  const results: CheckResult[] = [];

  const httpsResult = (key: string, probe: typeof httpsApex, label: string): CheckResult => {
    if (probe.error && probe.status === 0) return fail(key, `${label} did not respond: ${probe.error}`);
    if (statusOk(probe.status)) return pass(key, `${label} responded ${probe.status}`);
    return fail(key, `${label} responded ${probe.status || "no status"}`);
  };
  results.push(httpsResult("https-apex", httpsApex, "Apex"));
  results.push(
    t.wwwReachable
      ? httpsResult("https-www", httpsWww, "www")
      : skip("https-www", "www does not resolve; the apex is the only host"),
  );

  const httpRedirect = (key: string, probe: typeof httpApex, label: string): CheckResult => {
    const first = probe.hops[0];
    if (!first) return warn(key, `${label} could not be tested`);
    if (first.status === 301 || first.status === 308) {
      return first.location.startsWith("https://")
        ? pass(key, `${first.status} to ${first.location}`)
        : fail(key, `${first.status} but not to HTTPS`);
    }
    if (first.status >= 300 && first.status < 400) {
      return warn(key, `${first.status} to ${first.location}; use 301 or 308`);
    }
    if (first.status === 200) return fail(key, "HTTP served content without redirecting");
    if (first.status === 0) return warn(key, `HTTP could not be reached (${probe.error ?? "no response"})`);
    return warn(key, `HTTP returned ${first.status}`);
  };
  results.push(httpRedirect("http-https-apex", httpApex, "HTTP apex"));
  results.push(
    t.wwwReachable
      ? httpRedirect("http-https-www", httpWww, "HTTP www")
      : skip("http-https-www", "www does not resolve; the apex is the only host"),
  );

  results.push(
    cert
      ? cert.authorized
        ? pass("cert-apex", `${cert.issuerOrganisation || cert.issuer} · expires ${certDate(cert.validTo)}${t.tls.apex?.grade ? ` · SSL Labs ${t.tls.apex.grade}` : ""}`)
        : fail("cert-apex", `Certificate is not trusted: ${cert.authorizationError}`)
      : t.tls.apex?.error
        ? warn("cert-apex", `Certificate check unavailable: ${t.tls.apex.error}`)
        : fail("cert-apex", "No certificate could be read from the apex"),
  );
  const wwwCovered = Boolean(
    cert &&
      cert.sans.some((name) => name === facts.domain || name === `www.${facts.domain}` || name === `*.${facts.domain}`),
  );
  results.push(
    !t.wwwReachable
      ? skip("cert-www", "www does not resolve")
      : certWww
        ? !wwwCovered
          ? fail("cert-www", `Certificate names do not cover www.${facts.domain}`)
          : certWww.authorized
            ? pass("cert-www", `${certWww.issuerOrganisation || certWww.issuer} · expires ${certDate(certWww.validTo)}`)
            : fail("cert-www", `Certificate is not trusted: ${certWww.authorizationError}`)
        : t.tls.www?.error
          ? warn("cert-www", `Certificate check unavailable: ${t.tls.www.error}`)
          : fail("cert-www", "No certificate could be read from www"),
  );

  if (cert) {
    const days = cert.daysRemaining;
    results.push(
      days <= 0
        ? fail("cert-validity", `Expired ${Math.abs(days)} days ago`)
        : days < 30
          ? warn("cert-validity", `${days} days remaining`)
          : pass("cert-validity", `${days} days remaining`),
    );
    results.push(
      !cert.authorized
        ? fail("cert-chain", `Chain rejected: ${cert.authorizationError}`)
        : cert.chainLength >= 2
          ? pass("cert-chain", `${cert.chainLength} certificates in the chain`)
          : warn("cert-chain", "Only the leaf certificate was returned"),
    );
    results.push(
      cert.authorized
        ? pass("cert-hostname", `Covers ${cert.sans.slice(0, 4).join(", ") || cert.subject}`)
        : /hostname|altnames|does not match/i.test(cert.authorizationError)
          ? fail("cert-hostname", cert.authorizationError)
          : warn("cert-hostname", cert.authorizationError || "Could not verify the hostname"),
    );
  } else {
    results.push(skip("cert-validity", "No certificate"));
    results.push(skip("cert-chain", "No certificate"));
    results.push(skip("cert-hostname", "No certificate"));
  }

  const versions = t.tls.apex?.versions ?? {};
  const versionResult = (key: string, label: string): CheckResult => {
    const value = versions[label];
    if (!value) return skip(key, "Not measured");
    if (value.supported === true) return pass(key, `${value.protocol || label} negotiated`);
    if (value.supported === false) return fail(key, `${label} handshake failed`);
    return skip(key, `Could not test ${label} from this runtime`);
  };
  results.push(versionResult("tls12", "tls12"));
  results.push(versionResult("tls13", "tls13"));
  const legacy = versions.legacy;
  results.push(
    !legacy || legacy.supported === null
      ? skip("tls-legacy", "Could not test legacy TLS from this runtime")
      : legacy.supported
        ? fail("tls-legacy", `${legacy.protocol || "TLS 1.0/1.1"} is still accepted`)
        : pass("tls-legacy", "TLS 1.0 and 1.1 are rejected"),
  );

  const tls = t.tls.apex;
  results.push(
    tls?.ocspStapling === null || tls?.ocspStapling === undefined
      ? skip("ocsp-stapling", "Not measured")
      : tls.ocspStapling
        ? pass("ocsp-stapling", "OCSP response is stapled")
        : warn("ocsp-stapling", "OCSP stapling is not enabled"),
  );
  results.push(
    tls?.hasSct === null || tls?.hasSct === undefined
      ? skip("certificate-transparency", "Not measured")
      : tls.hasSct
        ? pass("certificate-transparency", "Certificate carries embedded SCTs")
        : warn("certificate-transparency", "No embedded SCTs"),
  );
  results.push(
    tls?.supportsAead === null || tls?.supportsAead === undefined
      ? skip("cipher-strength", "Not measured")
      : tls.supportsRc4
        ? fail("cipher-strength", "RC4 is still offered")
        : tls.supportsAead
          ? pass("cipher-strength", "AEAD suites offered; no RC4")
          : warn("cipher-strength", "No AEAD suite reported"),
  );
  results.push(
    tls?.forwardSecrecy === null || tls?.forwardSecrecy === undefined
      ? skip("forward-secrecy", "Not measured")
      : tls.forwardSecrecy > 0
        ? pass("forward-secrecy", "Ephemeral key exchange is offered")
        : warn("forward-secrecy", "No forward secrecy reported"),
  );

  const certDates = tls?.certificate;
  const validFrom = certDates?.validFrom ? new Date(certDates.validFrom).valueOf() : 0;
  const validTo = certDates?.validTo ? new Date(certDates.validTo).valueOf() : 0;
  const lifetimeDays = validFrom && validTo ? Math.round((validTo - validFrom) / 86_400_000) : 0;
  const lifetimeLimit = certLifetimeLimit(validFrom);
  results.push(
    !certDates || !lifetimeDays
      ? skip("cert-lifetime", "Certificate dates unavailable")
      : lifetimeDays > lifetimeLimit
        ? warn("cert-lifetime", `${lifetimeDays} days; the CA/B limit is ${lifetimeLimit} for this issue date`)
        : pass("cert-lifetime", `${lifetimeDays} days (limit ${lifetimeLimit})`),
  );
  const keyAlgorithm = (certDates?.keyAlgorithm ?? "").toLowerCase();
  const keySize = certDates?.keySize ?? null;
  results.push(
    !keyAlgorithm
      ? skip("cert-key-size", "Certificate key details unavailable")
      : keyAlgorithm.includes("ed25519") || keyAlgorithm.includes("ed448")
        ? pass("cert-key-size", keyAlgorithm.toUpperCase())
        : keySize === null
          ? skip("cert-key-size", "Certificate key size unavailable")
          : keyAlgorithm.includes("rsa") && keySize < 2048
            ? fail("cert-key-size", `RSA ${keySize}-bit`)
            : keyAlgorithm.includes("dsa") && keySize < 2048
              ? fail("cert-key-size", `DSA ${keySize}-bit`)
              : keyAlgorithm.includes("ec") && keySize < 256
                ? warn("cert-key-size", `EC ${keySize}-bit; use 256+`)
                : pass("cert-key-size", `${keyAlgorithm.toUpperCase()} ${keySize}-bit`),
  );

  results.push(
    t.hsts.apex.present
      ? pass("hsts-apex", t.hsts.apex.raw)
      : fail("hsts-apex", "No Strict-Transport-Security header on the apex"),
  );
  results.push(
    !t.wwwReachable
      ? skip("hsts-www", "www does not resolve")
      : t.hsts.www.present
        ? pass("hsts-www", t.hsts.www.raw)
        : fail("hsts-www", "No Strict-Transport-Security header on www"),
  );

  const hsts = t.hsts.apex.present ? t.hsts.apex : t.hsts.www;
  results.push(
    !hsts.present
      ? fail("hsts-max-age", "No HSTS header")
      : (hsts.maxAge ?? 0) >= 15_552_000
        ? pass("hsts-max-age", `max-age=${hsts.maxAge}`)
        : warn("hsts-max-age", `max-age=${hsts.maxAge ?? 0}; aim for at least 15552000`),
  );
  results.push(
    !hsts.present
      ? fail("hsts-subdomains", "No HSTS header")
      : hsts.includeSubDomains
        ? pass("hsts-subdomains", "includeSubDomains is set")
        : warn("hsts-subdomains", "includeSubDomains is missing"),
  );
  results.push(
    !hsts.present
      ? fail("hsts-preload", "No HSTS header")
      : hsts.preload
        ? pass("hsts-preload", "preload is requested in the header")
        : warn("hsts-preload", "preload is not requested"),
  );
  results.push(
    t.hsts.preloadStatus === null
      ? skip("hsts-preload-list", "Preload list status could not be checked")
      : t.hsts.preloadStatus === "preloaded"
        ? pass("hsts-preload-list", "Listed as preloaded")
        : warn("hsts-preload-list", `Preload list status: ${t.hsts.preloadStatus}`),
  );

  results.push(t.ipv6 ? pass("ipv6", "AAAA record published") : warn("ipv6", "No AAAA record"));
  results.push(t.http2 ? pass("http2", "HTTP/2 negotiated") : info("http2", "HTTP/2 could not be confirmed from this runtime"));
  results.push(t.http3 ? pass("http3", "HTTP/3 advertised via alt-svc") : info("http3", "HTTP/3 not advertised"));

  const mixed = facts.html?.mixedContent ?? [];
  results.push(
    mixed.length === 0
      ? pass("mixed-content", "No HTTP subresources on the homepage")
      : fail("mixed-content", `${mixed.length} HTTP subresource${mixed.length === 1 ? "" : "s"}`, mixed.slice(0, 5).join("\n")),
  );

  return results;
}

/* ------------------------------------------------------------------ */
/* Redirects                                                          */
/* ------------------------------------------------------------------ */

export function redirectChecks(facts: AuditFacts): CheckResult[] {
  const t = facts.transport;
  if (!t) {
    return ["host-duplicate", "redirect-chain", "redirect-status", "redirect-path-query", "trailing-slash", "index-html", "uppercase-host", "deep-path", "not-found", "canonical-host"].map((key) => skip(key, "Redirect checks could not run"));
  }

  const httpsApex = t.probes[1];
  const httpsWww = t.probes[3];
  const results: CheckResult[] = [];

  if (!t.wwwReachable) {
    results.push(pass("host-duplicate", "www does not resolve; one host serves the site"));
  } else {
    const apexFirst = httpsApex.hops[0]?.status ?? httpsApex.status;
    const wwwFirst = httpsWww.hops[0]?.status ?? httpsWww.status;
    const apex200 = apexFirst === 200;
    const www200 = wwwFirst === 200;
    if (apex200 && www200) {
      const same = Boolean(httpsApex.bodyHash && httpsWww.bodyHash && httpsApex.bodyHash === httpsWww.bodyHash);
      results.push(fail("host-duplicate", same ? "Both apex and www return 200 with identical content" : "Both apex and www return 200"));
    } else {
      results.push(pass("host-duplicate", `Apex ${apexFirst}, www ${wwwFirst}`));
    }
  }

  const maxHops = Math.max(...t.probes.map((probe) => probe.hops.length), 0);
  results.push(
    maxHops > 3 ? fail("redirect-chain", `${maxHops} hops in the longest chain`) : maxHops > 2 ? warn("redirect-chain", `${maxHops} hops in the longest chain`) : pass("redirect-chain", `${maxHops} hop${maxHops === 1 ? "" : "s"} at most`),
  );

  const redirectHops = t.probes.flatMap((probe) => probe.hops.filter((hop) => hop.status >= 300 && hop.status < 400));
  const temporary = redirectHops.filter((hop) => hop.status === 302 || hop.status === 303 || hop.status === 307);
  results.push(
    temporary.length
      ? warn("redirect-status", `${temporary.length} temporary redirect${temporary.length === 1 ? "" : "s"} (${temporary[0].status})`)
      : pass("redirect-status", redirectHops.length ? "Permanent redirects only" : "No redirects to judge"),
  );

  const pathFirst = t.pathProbe.hops[0];
  const pathPreserved =
    t.pathProbe.finalUrl.includes("/lexiphanic-audit") &&
    (!pathFirst?.location || pathFirst.location.includes("/lexiphanic-audit"));
  results.push(
    t.pathProbe.error
      ? skip("redirect-path-query", "Path probe could not run")
      : pathPreserved
        ? pass("redirect-path-query", "Path is preserved across the host redirect")
        : fail("redirect-path-query", `Path was lost; final URL is ${t.pathProbe.finalUrl}`),
  );

  results.push(info("trailing-slash", "Checked through canonical and index.html, not by forcing a 404 path"));

  if (t.indexProbe.error) {
    results.push(skip("index-html", "Could not test /index.html"));
  } else if (t.indexProbe.status >= 300 && t.indexProbe.status < 400) {
    results.push(pass("index-html", `${t.indexProbe.status} to ${t.indexProbe.location}`));
  } else if (t.indexProbe.status === 404 || t.indexProbe.status === 410) {
    results.push(pass("index-html", "/index.html is not served"));
  } else if (t.indexProbe.status === 200) {
    const duplicate = Boolean(t.indexProbe.bodyHash && httpsApex.bodyHash && t.indexProbe.bodyHash === httpsApex.bodyHash);
    results.push(duplicate ? fail("index-html", "/index.html serves the same content as /") : warn("index-html", "/index.html returns 200"));
  } else {
    results.push(warn("index-html", `/index.html returned ${t.indexProbe.status}`));
  }

  results.push(info("uppercase-host", "Host casing is normalised by browsers; DNS and TLS already cover the host"));

  const finalHost = hostOf(t.pathProbe.finalUrl);
  const expectedHosts = new Set([facts.domain, `www.${facts.domain}`]);
  results.push(
    t.pathProbe.error
      ? skip("deep-path", "Deep path probe could not run")
      : expectedHosts.has(finalHost)
        ? pass("deep-path", `Deep path resolves on ${finalHost}`)
        : fail("deep-path", `Deep path landed on ${finalHost || "an unknown host"}`),
  );

  if (t.notFoundProbe.error) {
    results.push(skip("not-found", "Could not test a missing path"));
  } else if (t.notFoundProbe.status === 404 || t.notFoundProbe.status === 410) {
    results.push(pass("not-found", `Missing path returned ${t.notFoundProbe.status}`));
  } else if (t.notFoundProbe.status === 200) {
    results.push(fail("not-found", "Missing path returned 200 (soft 404)"));
  } else {
    results.push(warn("not-found", `Missing path returned ${t.notFoundProbe.status}`));
  }

  const canonical = facts.html?.canonical ?? "";
  if (!canonical) {
    results.push(fail("canonical-host", "No canonical URL"));
  } else {
    const canonicalHost = hostOf(canonical);
    const finalUrlHost = hostOf(t.homepage.finalUrl);
    results.push(
      canonicalHost === finalUrlHost
        ? pass("canonical-host", `Canonical points at ${canonicalHost}`)
        : fail("canonical-host", `Canonical points at ${canonicalHost}, but the page is served from ${finalUrlHost}`),
    );
  }

  return results;
}

/* ------------------------------------------------------------------ */
/* Metadata                                                           */
/* ------------------------------------------------------------------ */

export function metadataChecks(facts: AuditFacts): CheckResult[] {
  const h = facts.html;
  if (!h) {
    return ["title", "title-length", "description", "description-length", "canonical", "canonical-self", "robots-meta", "og-basic", "og-image", "og-image-reachable", "og-image-metadata", "twitter-card", "favicon", "manifest", "apple-touch-icon", "apple-touch-icon-size", "manifest-fields", "manifest-icons", "theme-color", "mask-icon", "jsonld", "jsonld-valid", "hreflang", "canonical-og-url", "lang", "charset", "viewport", "headings", "alt-text", "duplicate-meta"].map((key) => skip(key, "Metadata could not be read"));
  }

  const results: CheckResult[] = [];
  const normalizeUrl = (value: string): string => {
    try {
      return new URL(value, h.finalUrl).href.replace(/\/$/, "");
    } catch {
      return value.trim().replace(/\/$/, "");
    }
  };
  results.push(h.title ? pass("title", h.title) : fail("title", "No title tag"));
  results.push(
    !h.title
      ? skip("title-length", "No title")
      : h.title.length >= 15 && h.title.length <= 60
        ? pass("title-length", `${h.title.length} characters`)
        : h.title.length >= 10 && h.title.length <= 70
          ? warn("title-length", `${h.title.length} characters`)
          : fail("title-length", `${h.title.length} characters`),
  );
  results.push(h.description ? pass("description", h.description) : fail("description", "No meta description"));
  results.push(
    !h.description
      ? skip("description-length", "No description")
      : h.description.length >= 50 && h.description.length <= 160
        ? pass("description-length", `${h.description.length} characters`)
        : h.description.length >= 30 && h.description.length <= 180
          ? warn("description-length", `${h.description.length} characters`)
          : fail("description-length", `${h.description.length} characters`),
  );
  results.push(h.canonical ? pass("canonical", h.canonical) : fail("canonical", "No canonical link"));
  results.push(
    !h.canonical
      ? skip("canonical-self", "No canonical link")
      : normalizeUrl(h.canonical) === normalizeUrl(h.finalUrl)
        ? pass("canonical-self", "Canonical points at this page")
        : warn("canonical-self", `Canonical points at ${h.canonical}`),
  );
  results.push(/noindex/i.test(h.robots) ? fail("robots-meta", h.robots) : pass("robots-meta", h.robots || "No robots meta; index/follow is implied"));

  const ogRequired = ["og:title", "og:description", "og:type", "og:url", "og:site_name"];
  const ogPresent = ogRequired.filter((key) => h.og[key]);
  results.push(
    ogPresent.length === ogRequired.length
      ? pass("og-basic", `All ${ogRequired.length} core Open Graph tags present`)
      : ogPresent.length >= 3
        ? warn("og-basic", `${ogPresent.length} of ${ogRequired.length} core tags present`)
        : fail("og-basic", `${ogPresent.length} of ${ogRequired.length} core tags present`),
  );
  results.push(h.og["og:image"] ? pass("og-image", h.og["og:image"]) : fail("og-image", "No og:image"));
  results.push(
    !h.og["og:image"]
      ? skip("og-image-reachable", "No og:image")
      : h.ogImageStatus >= 200 && h.ogImageStatus < 300
        ? pass("og-image-reachable", `Image returned ${h.ogImageStatus}`)
        : fail("og-image-reachable", `Image returned ${h.ogImageStatus || "no response"}`),
  );
  const ogImageMeta = ["og:image:width", "og:image:height", "og:image:alt"];
  const ogImagePresent = ogImageMeta.filter((key) => h.og[key]);
  results.push(
    !h.og["og:image"]
      ? skip("og-image-metadata", "No og:image")
      : ogImagePresent.length === ogImageMeta.length
        ? pass("og-image-metadata", "Width, height and alt are present")
        : warn(
            "og-image-metadata",
            `${ogImagePresent.length} of ${ogImageMeta.length} tags present: ${ogImageMeta.filter((key) => !h.og[key]).join(", ")} missing`,
          ),
  );

  const twitterRequired = ["twitter:card", "twitter:title", "twitter:description", "twitter:image"];
  const twitterPresent = twitterRequired.filter((key) => h.twitter[key]);
  results.push(
    twitterPresent.length === twitterRequired.length
      ? pass("twitter-card", "All core Twitter card tags present")
      : twitterPresent.length
        ? warn("twitter-card", `${twitterPresent.length} of ${twitterRequired.length} tags present`)
        : warn("twitter-card", "No Twitter card tags"),
  );

  results.push(h.icons.length || facts.files?.rootIcons.favicon ? pass("favicon", h.icons.map((icon) => icon.href).slice(0, 3).join(", ") || "/favicon.ico") : fail("favicon", "No favicon found"));
  results.push(facts.files?.manifest ? pass("manifest", h.manifestHref || "Web manifest found") : warn("manifest", "No web manifest"));

  const files = facts.files;
  const appleIcons = files?.appleTouchIcons ?? [];
  const appleVerified = appleIcons.filter((icon) => statusOk(icon.status));
  const appleDeclared = h.icons.some((icon) => /apple-touch-icon/i.test(icon.rel));
  const appleLoaded = appleVerified.find((icon) =>
    /^image\//i.test(icon.contentType || icon.declaredType),
  );
  const appleBytes = appleLoaded?.bytes
    ? `, ${Math.max(1, Math.round(appleLoaded.bytes / 1024))} KB`
    : "";
  results.push(
    appleLoaded
      ? pass(
          "apple-touch-icon",
          `${appleLoaded.href}${appleLoaded.sizes ? ` (${appleLoaded.sizes})` : ""}${appleBytes}`,
        )
      : appleIcons.length
        ? warn(
            "apple-touch-icon",
            appleIcons
              .map((icon) => `${icon.href} returned ${icon.status || icon.error || "no response"}`)
              .slice(0, 2)
              .join("; "),
          )
        : appleDeclared
          ? warn("apple-touch-icon", "Declared but could not be verified")
          : files?.rootIcons.appleTouch
            ? warn("apple-touch-icon", "/apple-touch-icon.png exists but is not declared in the head")
            : warn("apple-touch-icon", "No apple-touch-icon declared"),
  );

  const appleSizes = appleVerified
    .flatMap((icon) => icon.sizes.split(/\s+/))
    .map((size) => /^(\d+)x(\d+)$/i.exec(size))
    .filter((match): match is RegExpExecArray => Boolean(match))
    .map((match) => Math.min(Number(match[1]), Number(match[2])));
  const largestApple = appleSizes.length ? Math.max(...appleSizes) : 0;
  results.push(
    !appleVerified.length
      ? skip(
          "apple-touch-icon-size",
          appleIcons.length || appleDeclared ? "Icon could not be verified" : "No apple-touch-icon",
        )
      : largestApple >= 180
        ? pass("apple-touch-icon-size", `${largestApple}px declared`)
        : largestApple > 0
          ? warn("apple-touch-icon-size", `${largestApple}px declared; use at least 180×180`)
          : warn("apple-touch-icon-size", "No sizes attribute; declare 180x180"),
  );

  results.push(
    !h.themeColor
      ? warn("theme-color", "No theme-color meta")
      : /^(#[0-9a-f]{3,8}|(?:rgb|hsl|oklch|lab|lch|color)\(|transparent$)/i.test(h.themeColor.trim())
        ? pass("theme-color", h.themeColor)
        : warn("theme-color", `Unrecognised colour: ${h.themeColor}`),
  );

  const mask = files?.maskIcon ?? null;
  const maskDeclared = h.icons.some((icon) => /(^|\s)mask-icon(\s|$)/i.test(icon.rel));
  results.push(
    !maskDeclared
      ? info("mask-icon", "No mask-icon link")
      : !mask
        ? skip("mask-icon", "Icon could not be verified")
        : statusOk(mask.status)
          ? pass("mask-icon", mask.href)
          : warn("mask-icon", `${mask.href} returned ${mask.status || "no response"}`),
  );

  const manifest = files?.manifestDetails;
  if (!files) {
    results.push(skip("manifest-fields", "Crawl files could not be read"));
    results.push(skip("manifest-icons", "Crawl files could not be read"));
  } else if (!manifest?.present) {
    results.push(skip("manifest-fields", "No manifest"));
    results.push(skip("manifest-icons", "No manifest"));
  } else if (!manifest.valid) {
    results.push(fail("manifest-fields", manifest.error || "Manifest did not parse"));
    results.push(fail("manifest-icons", "Manifest did not parse"));
  } else {
    const core = [
      manifest.name || manifest.shortName ? "name" : "",
      manifest.startUrl ? "start_url" : "",
      manifest.display ? "display" : "",
      manifest.themeColor || manifest.backgroundColor ? "theme_color" : "",
    ].filter(Boolean);
    const manifestSource = manifest.href
      ? ` · ${manifest.href}${manifest.status ? ` (${manifest.status})` : ""}`
      : "";
    results.push(
      core.length === 4
        ? pass("manifest-fields", `name, start_url, display and theme_color present${manifestSource}`)
        : core.length >= 2
          ? warn("manifest-fields", `${core.length} of 4 core fields present: ${core.join(", ")}${manifestSource}`)
          : fail("manifest-fields", `Only ${core.length} of 4 core fields present${manifestSource}`),
    );
    const has192 = manifest.iconSizes.includes("192x192");
    const has512 = manifest.iconSizes.includes("512x512");
    const maskable = manifest.icons.some((icon) => /maskable/i.test(icon.purpose));
    results.push(
      !manifest.icons.length
        ? fail("manifest-icons", "No icons in the manifest")
        : has192 && has512
          ? pass(
              "manifest-icons",
              `${manifest.icons.length} icons, including 192×192 and 512×512${maskable ? ", one maskable" : ""}`,
            )
          : warn(
              "manifest-icons",
              `${manifest.icons.length} icons; ${has192 ? "" : "192×192 missing "}${has512 ? "" : "512×512 missing"}${maskable ? "" : " · no maskable icon"}`.trim(),
            ),
    );
  }

  const jsonLd = h.jsonLd;
  results.push(jsonLd.length ? pass("jsonld", `${jsonLd.length} block${jsonLd.length === 1 ? "" : "s"}: ${[...new Set(jsonLd.map((item) => item.type))].slice(0, 6).join(", ")}`) : warn("jsonld", "No JSON-LD"));
  results.push(
    !jsonLd.length
      ? skip("jsonld-valid", "No JSON-LD")
      : jsonLd.every((item) => item.valid)
        ? pass("jsonld-valid", "All blocks parse")
        : fail("jsonld-valid", `${jsonLd.filter((item) => !item.valid).length} invalid block${jsonLd.filter((item) => !item.valid).length === 1 ? "" : "s"}`),
  );

  results.push(
    !h.hreflang.length
      ? info("hreflang", "No hreflang; treated as a single-language site")
      : h.hreflang.some((item) => item.lang === "x-default") && h.hreflang.every((item) => item.href.startsWith("http"))
        ? pass("hreflang", `${h.hreflang.length} hreflang entries with x-default`)
        : warn("hreflang", `${h.hreflang.length} entries; check reciprocity and x-default`),
  );
  const ogUrl = h.og["og:url"] ?? "";
  results.push(
    !h.canonical || !ogUrl
      ? info("canonical-og-url", "Canonical or og:url is missing")
      : normalizeUrl(h.canonical) === normalizeUrl(ogUrl)
        ? pass("canonical-og-url", "Canonical and og:url agree")
        : warn("canonical-og-url", `canonical ${h.canonical} vs og:url ${ogUrl}`),
  );
  results.push(h.lang ? pass("lang", h.lang) : fail("lang", "No lang attribute"));
  results.push(/utf-?8/i.test(h.charset) ? pass("charset", h.charset) : warn("charset", h.charset || "No charset declared"));
  results.push(/width\s*=\s*device-width/i.test(h.viewport) ? pass("viewport", h.viewport) : fail("viewport", h.viewport || "No viewport meta"));

  const h1 = h.headings.filter((heading) => heading.level === 1);
  results.push(h1.length === 1 ? pass("headings", `One H1: ${h1[0].text}`) : h1.length === 0 ? fail("headings", "No H1") : warn("headings", `${h1.length} H1 elements`));

  const missingAlt = h.images.filter((image) => !image.alt.trim()).length;
  results.push(
    !h.images.length
      ? info("alt-text", "No images on the homepage")
      : missingAlt === 0
        ? pass("alt-text", `All ${h.images.length} images have alt text`)
        : missingAlt / h.images.length > 0.2
          ? fail("alt-text", `${missingAlt} of ${h.images.length} images lack alt text`)
          : warn("alt-text", `${missingAlt} of ${h.images.length} images lack alt text`),
  );
  results.push(h.duplicateMeta === 0 ? pass("duplicate-meta", "No duplicate title/canonical/meta keys") : warn("duplicate-meta", `${h.duplicateMeta} duplicate tag${h.duplicateMeta === 1 ? "" : "s"}`));

  return results;
}

/* ------------------------------------------------------------------ */
/* Crawl                                                              */
/* ------------------------------------------------------------------ */

export function crawlChecks(facts: AuditFacts): CheckResult[] {
  const f = facts.files;
  const h = facts.html;
  if (!f) {
    return ["robots-exists", "robots-valid", "robots-sitemap", "robots-blocks", "robots-ai", "sitemap-exists", "sitemap-valid", "sitemap-host", "sitemap-sample", "sitemap-lastmod", "sitemap-titles", "sitemap-noindex", "sitemap-descriptions", "sitemap-canonical", "x-robots-tag", "noindex", "custom-404", "feed", "internal-links", "llms-txt", "llms-full", "ai-txt", "semantic-headings"].map((key) => skip(key, "Crawl files could not be read"));
  }

  const results: CheckResult[] = [];
  results.push(f.robots.present ? pass("robots-exists", `robots.txt returned ${f.robots.status}`) : fail("robots-exists", "No robots.txt"));
  results.push(
    f.robots.present && f.robots.status === 200
      ? pass("robots-valid", "robots.txt returned 200")
      : warn("robots-valid", f.robots.present ? `robots.txt returned ${f.robots.status}` : "No robots.txt"),
  );
  results.push(f.robots.sitemaps.length ? pass("robots-sitemap", f.robots.sitemaps.join(", ")) : warn("robots-sitemap", "No Sitemap: line"));
  results.push(f.robots.blocksAll ? fail("robots-blocks", "Disallow: / for *") : pass("robots-blocks", "The wildcard group does not block the site"));
  const explicitAi = Object.values(f.robots.aiRules).filter((rules) => rules !== null).length;
  results.push(explicitAi ? pass("robots-ai", `${explicitAi} AI user-agent groups declared`) : info("robots-ai", "No named AI crawler rules"));

  results.push(f.sitemaps.present ? pass("sitemap-exists", f.sitemaps.source) : fail("sitemap-exists", "No sitemap found"));
  results.push(f.sitemaps.valid ? pass("sitemap-valid", `${f.sitemaps.count} URLs`) : fail("sitemap-valid", "Sitemap did not parse"));
  const wrongHost = f.sitemaps.urls.filter((url) => {
    const host = hostOf(url);
    return host && host !== facts.domain && host !== `www.${facts.domain}`;
  });
  results.push(
    !f.sitemaps.urls.length
      ? skip("sitemap-host", "No sitemap URLs")
      : wrongHost.length
        ? fail("sitemap-host", `${wrongHost.length} URLs on another host`, wrongHost.slice(0, 5).join("\n"))
        : pass("sitemap-host", "All sampled URLs use the canonical host"),
  );
  const badSamples = f.sitemaps.sample.filter((sample) => sample.status >= 400 || sample.status === 0);
  results.push(
    !f.sitemaps.sample.length
      ? skip("sitemap-sample", "No sitemap URLs to sample")
      : badSamples.length === 0
        ? pass("sitemap-sample", `${f.sitemaps.sample.length} sampled URLs resolve`)
        : badSamples.length <= 2
          ? warn("sitemap-sample", `${badSamples.length} of ${f.sitemaps.sample.length} sampled URLs failed`)
          : fail("sitemap-sample", `${badSamples.length} of ${f.sitemaps.sample.length} sampled URLs failed`),
  );
  results.push(
    !f.sitemaps.lastmod
      ? info("sitemap-lastmod", "No lastmod values")
      : new Date(f.sitemaps.lastmod).valueOf() > Date.now() + 86_400_000
        ? warn("sitemap-lastmod", `lastmod is in the future: ${f.sitemaps.lastmod}`)
        : pass("sitemap-lastmod", f.sitemaps.lastmod),
  );
  const pages = f.sitemaps.pages ?? [];
  const missingTitles = pages.filter((entry) => !entry.title.trim()).length;
  results.push(
    pages.length < 2
      ? skip("sitemap-titles", "Not enough sampled pages")
      : f.sitemaps.duplicateTitles.length
        ? warn(
            "sitemap-titles",
            `${f.sitemaps.duplicateTitles.length} duplicate title${f.sitemaps.duplicateTitles.length === 1 ? "" : "s"}`,
            f.sitemaps.duplicateTitles.slice(0, 3).join("; "),
          )
        : missingTitles
          ? warn("sitemap-titles", `${missingTitles} of ${pages.length} sampled pages have no title`)
          : pass("sitemap-titles", `${pages.length} sampled pages have distinct titles`),
  );
  const noindexPages = pages.filter((entry) => /noindex/i.test(`${entry.robots} ${entry.xRobots}`));
  results.push(
    pages.length < 2
      ? skip("sitemap-noindex", "Not enough sampled pages")
      : noindexPages.length
        ? fail(
            "sitemap-noindex",
            `${noindexPages.length} of ${pages.length} sampled pages are noindex`,
            noindexPages.map((entry) => entry.url).slice(0, 5).join("\n"),
          )
        : pass("sitemap-noindex", `${pages.length} sampled pages are indexable`),
  );
  const descriptions = pages
    .map((entry) => entry.description.trim().toLowerCase())
    .filter(Boolean);
  const duplicateDescriptions = [...new Set(descriptions.filter((value, index) => descriptions.indexOf(value) !== index))];
  const missingDescriptions = pages.filter((entry) => !entry.description.trim()).length;
  results.push(
    pages.length < 2
      ? skip("sitemap-descriptions", "Not enough sampled pages")
      : duplicateDescriptions.length
        ? warn(
            "sitemap-descriptions",
            `${duplicateDescriptions.length} duplicate description${duplicateDescriptions.length === 1 ? "" : "s"}`,
            duplicateDescriptions.slice(0, 3).join("; "),
          )
        : missingDescriptions
          ? warn("sitemap-descriptions", `${missingDescriptions} of ${pages.length} sampled pages have no description`)
          : pass("sitemap-descriptions", `${pages.length} sampled pages have descriptions`),
  );
  const canonicalProblems = pages.filter((entry) => {
    if (!entry.canonical) return true;
    try {
      const pageUrl = new URL(entry.url);
      const canonical = new URL(entry.canonical, entry.url);
      return (
        hostOf(canonical.href) !== hostOf(pageUrl.href) ||
        canonical.pathname.replace(/\/$/, "") !== pageUrl.pathname.replace(/\/$/, "")
      );
    } catch {
      return true;
    }
  });
  results.push(
    pages.length < 2
      ? skip("sitemap-canonical", "Not enough sampled pages")
      : canonicalProblems.length
        ? warn(
            "sitemap-canonical",
            `${canonicalProblems.length} of ${pages.length} sampled pages do not canonicalise to themselves`,
            canonicalProblems.map((entry) => entry.url).slice(0, 5).join("\n"),
          )
        : pass("sitemap-canonical", `${pages.length} sampled pages have self-canonicals`),
  );

  const xRobots = facts.transport?.homepage.headers["x-robots-tag"] ?? "";
  results.push(/noindex/i.test(xRobots) ? fail("x-robots-tag", xRobots) : pass("x-robots-tag", xRobots || "No blocking X-Robots-Tag"));
  results.push(/noindex/i.test(h?.robots ?? "") || /noindex/i.test(xRobots) ? fail("noindex", "Homepage is noindex") : pass("noindex", "Homepage is indexable"));
  results.push(
    facts.transport?.notFoundProbe.status === 404 || facts.transport?.notFoundProbe.status === 410
      ? pass("custom-404", `Missing path returns ${facts.transport.notFoundProbe.status}`)
      : warn("custom-404", "Could not confirm a 404 response"),
  );

  const feed = h?.links.some((link) => /\/(feed|rss|atom)(\/|\.xml|$)/i.test(link.href)) ?? false;
  results.push(feed ? pass("feed", "A feed link is present") : info("feed", "No feed link found"));
  results.push(
    !facts.performance
      ? skip("internal-links", "Link sample could not run")
      : facts.performance.brokenLinks.length === 0
        ? pass("internal-links", "Sampled internal links resolve")
        : warn("internal-links", `${facts.performance.brokenLinks.length} sampled link${facts.performance.brokenLinks.length === 1 ? "" : "s"} failed`, facts.performance.brokenLinks.join("\n")),
  );

  results.push(f.llms.root || f.llms.wellKnown ? pass("llms-txt", f.llms.root ? "/llms.txt" : "/.well-known/llms.txt") : warn("llms-txt", "No llms.txt"));
  results.push(f.llms.full ? pass("llms-full", "/llms-full.txt") : info("llms-full", "No llms-full.txt"));
  results.push(f.aiTxt ? pass("ai-txt", "/ai.txt") : info("ai-txt", "No ai.txt"));
  results.push(
    h?.hasMain && h.hasSkipLink
      ? pass("semantic-headings", "main landmark and skip link present")
      : h?.hasMain
        ? warn("semantic-headings", "main landmark present; no skip link")
        : warn("semantic-headings", "No main landmark"),
  );

  return results;
}

/* ------------------------------------------------------------------ */
/* Well-known                                                         */
/* ------------------------------------------------------------------ */

export function wellknownChecks(facts: AuditFacts): CheckResult[] {
  const f = facts.files;
  if (!f) {
    return ["security-txt", "security-txt-root", "security-txt-expiry", "security-txt-contact", "security-txt-canonical", "security-txt-type", "change-password", "aasa", "assetlinks", "mta-sts-file", "gpc", "trust-txt", "nodeinfo", "webfinger", "host-meta", "humans-txt", "ads-txt", "browserconfig", "root-icons"].map((key) => skip(key, "Well-known files could not be read"));
  }

  const s = f.securityTxt;
  const contact = s.fields.contact?.[0] ?? "";
  const results: CheckResult[] = [];
  results.push(s.present ? pass("security-txt", s.path) : fail("security-txt", "No security.txt"));
  results.push(
    (f.entries["/security.txt"]?.status ?? 0) >= 200 && (f.entries["/security.txt"]?.status ?? 0) < 400
      ? pass("security-txt-root", "/security.txt works")
      : info("security-txt-root", "No /security.txt fallback"),
  );
  results.push(
    !s.present
      ? skip("security-txt-expiry", "No security.txt")
      : s.expired
        ? fail("security-txt-expiry", `Expired: ${s.fields.expires?.[0] ?? "unknown"}`)
        : pass("security-txt-expiry", s.fields.expires?.[0] ?? "No Expires field"),
  );
  results.push(
    !s.present
      ? skip("security-txt-contact", "No security.txt")
      : contact
        ? pass("security-txt-contact", contact)
        : fail("security-txt-contact", "No Contact field"),
  );
  results.push(
    !s.present
      ? skip("security-txt-canonical", "No security.txt")
      : s.canonical
        ? pass("security-txt-canonical", s.canonical)
        : warn("security-txt-canonical", "No Canonical field"),
  );
  results.push(
    !s.present
      ? skip("security-txt-type", "No security.txt")
      : /text\/plain/i.test(s.contentType)
        ? pass("security-txt-type", s.contentType)
        : warn("security-txt-type", s.contentType || "No content type"),
  );

  results.push(f.changePassword ? pass("change-password", "/.well-known/change-password responds") : info("change-password", "Not present"));
  results.push(f.aasa ? pass("aasa", "Apple association present") : info("aasa", "Not present"));
  results.push(f.assetlinks ? pass("assetlinks", "Android asset links present") : info("assetlinks", "Not present"));
  results.push(f.mtaSts ? pass("mta-sts-file", "/.well-known/mta-sts.txt responds") : info("mta-sts-file", "Not present"));
  results.push(f.gpc ? pass("gpc", "gpc.json present") : info("gpc", "Not present"));
  results.push(f.trustTxt ? pass("trust-txt", "trust.txt present") : info("trust-txt", "Not present"));
  results.push(f.nodeinfo ? pass("nodeinfo", "nodeinfo present") : info("nodeinfo", "Not present"));
  results.push(f.webfinger ? pass("webfinger", "webfinger responds") : info("webfinger", "Not present"));
  results.push(f.hostMeta ? pass("host-meta", "host-meta present") : info("host-meta", "Not present"));
  results.push(f.humansTxt ? pass("humans-txt", "humans.txt present") : info("humans-txt", "Not present"));
  results.push(f.adsTxt ? pass("ads-txt", "ads.txt present") : info("ads-txt", "Not present"));
  results.push(f.browserconfig ? pass("browserconfig", "browserconfig.xml present") : info("browserconfig", "Not present"));
  const declaredFavicon = Boolean(
    facts.html?.icons.some((icon) => /(^|\s)icon(\s|$)/i.test(icon.rel)),
  );
  const appleOk =
    f.rootIcons.appleTouch || (f.appleTouchIcons ?? []).some((icon) => statusOk(icon.status));
  const faviconOk = f.rootIcons.favicon || declaredFavicon;
  results.push(
    faviconOk && appleOk
      ? pass("root-icons", "Favicon and apple-touch-icon resolve")
      : warn(
          "root-icons",
          `${faviconOk ? "" : "favicon missing "}${appleOk ? "" : "apple-touch-icon missing"}`.trim(),
        ),
  );

  return results;
}

/* ------------------------------------------------------------------ */
/* Security                                                           */
/* ------------------------------------------------------------------ */

export function securityChecks(facts: AuditFacts): CheckResult[] {
  const s = facts.security;
  const d = facts.dns;
  if (!s) {
    return ["csp", "csp-unsafe", "csp-directives", "csp-report", "xcto", "frame-options", "referrer-policy", "permissions-policy", "coop", "corp", "coep", "origin-agent-cluster", "cross-domain-policy", "cookies-secure", "cookies-httponly", "cookies-samesite", "cookies-samesite-none", "sri", "forms-https", "trackers", "consent", "privacy-page", "cookie-page", "terms-page", "accessibility-page", "spf", "spf-records", "spf-lookups", "dkim", "dkim-key", "dmarc", "dmarc-reporting", "dmarc-testing", "dmarc-subdomains", "dmarc-obsolete-tags", "dmarc-external-report", "bimi", "bimi-assets", "mta-sts-dns", "mta-sts-policy", "tls-rpt", "tls-rpt-rua", "mx-redundancy", "dane-tlsa", "dnssec", "caa", "caa-issue", "registrar-lock", "registrar-expiry", "server-disclosure"].map((key) => skip(key, "Security checks could not run"));
  }

  const results: CheckResult[] = [];
  results.push(s.csp.present ? pass("csp", s.csp.reportOnly ? "Report-only policy present" : "Enforced policy present") : fail("csp", "No Content-Security-Policy"));
  results.push(
    !s.csp.present
      ? skip("csp-unsafe", "No CSP")
      : s.csp.unsafeInline || s.csp.unsafeEval
        ? fail("csp-unsafe", `${s.csp.unsafeInline ? "unsafe-inline " : ""}${s.csp.unsafeEval ? "unsafe-eval" : ""}`.trim())
        : pass("csp-unsafe", "No unsafe-inline or unsafe-eval"),
  );
  const directives = ["default-src", "object-src", "base-uri", "frame-ancestors"].filter((key) => s.csp.directives[key]);
  results.push(
    !s.csp.present
      ? skip("csp-directives", "No CSP")
      : directives.length === 4
        ? pass("csp-directives", "default-src, object-src, base-uri and frame-ancestors present")
        : warn("csp-directives", `${directives.length} of 4 core directives present`),
  );
  results.push(!s.csp.present ? skip("csp-report", "No CSP") : s.csp.reportUri ? pass("csp-report", "Reporting endpoint configured") : warn("csp-report", "No report-uri or report-to"));

  results.push(/nosniff/i.test(s.xcto) ? pass("xcto", s.xcto) : fail("xcto", s.xcto || "No X-Content-Type-Options"));
  results.push(
    /deny|sameorigin/i.test(s.frameOptions) || s.csp.directives["frame-ancestors"]
      ? pass("frame-options", s.frameOptions || "frame-ancestors in CSP")
      : fail("frame-options", "No frame protection"),
  );
  results.push(s.referrerPolicy ? (/unsafe-url/i.test(s.referrerPolicy) ? warn("referrer-policy", s.referrerPolicy) : pass("referrer-policy", s.referrerPolicy)) : warn("referrer-policy", "No Referrer-Policy"));
  results.push(s.permissionsPolicy ? pass("permissions-policy", s.permissionsPolicy) : warn("permissions-policy", "No Permissions-Policy"));
  results.push(s.coop ? pass("coop", s.coop) : info("coop", "Not set"));
  results.push(s.corp ? pass("corp", s.corp) : info("corp", "Not set"));
  const coep = s.headers["cross-origin-embedder-policy"] ?? "";
  results.push(
    /require-corp|credentialless/i.test(coep)
      ? pass("coep", coep)
      : info("coep", coep || "Not set; only needed for cross-origin isolation"),
  );
  const originAgentCluster = s.headers["origin-agent-cluster"] ?? "";
  results.push(
    /\?1/i.test(originAgentCluster)
      ? pass("origin-agent-cluster", originAgentCluster)
      : info("origin-agent-cluster", originAgentCluster || "Not set; optional"),
  );
  const crossDomainPolicy = s.headers["x-permitted-cross-domain-policies"] ?? "";
  results.push(
    /^(none|master-only)$/i.test(crossDomainPolicy.trim())
      ? pass("cross-domain-policy", crossDomainPolicy)
      : crossDomainPolicy
        ? warn("cross-domain-policy", crossDomainPolicy)
        : info("cross-domain-policy", "Not set"),
  );

  if (!s.cookies.length) {
    results.push(pass("cookies-secure", "No cookies set on the homepage"));
    results.push(pass("cookies-httponly", "No cookies set on the homepage"));
    results.push(pass("cookies-samesite", "No cookies set on the homepage"));
    results.push(pass("cookies-samesite-none", "No cookies set on the homepage"));
  } else {
    const insecure = s.cookies.filter((cookie) => !cookie.secure);
    const noHttpOnly = s.cookies.filter((cookie) => !cookie.httpOnly);
    const sensitiveNoHttpOnly = noHttpOnly.filter((cookie) => /sess|auth|token|login|user/i.test(cookie.name));
    const noSameSite = s.cookies.filter((cookie) => !cookie.sameSite);
    const noneInsecure = s.cookies.filter(
      (cookie) => /^none$/i.test(cookie.sameSite) && !cookie.secure,
    );
    results.push(insecure.length ? fail("cookies-secure", `${insecure.length} of ${s.cookies.length} cookies lack Secure`) : pass("cookies-secure", `All ${s.cookies.length} cookies are Secure`));
    results.push(sensitiveNoHttpOnly.length ? fail("cookies-httponly", `${sensitiveNoHttpOnly.length} session-like cookies lack HttpOnly`) : noHttpOnly.length ? warn("cookies-httponly", `${noHttpOnly.length} of ${s.cookies.length} cookies lack HttpOnly`) : pass("cookies-httponly", "All cookies are HttpOnly"));
    results.push(noSameSite.length ? warn("cookies-samesite", `${noSameSite.length} of ${s.cookies.length} cookies lack SameSite`) : pass("cookies-samesite", "All cookies set SameSite"));
    results.push(
      noneInsecure.length
        ? fail(
            "cookies-samesite-none",
            `${noneInsecure.length} cookie${noneInsecure.length === 1 ? "" : "s"} set SameSite=None without Secure`,
            noneInsecure.map((cookie) => cookie.name).join(", "),
          )
        : pass("cookies-samesite-none", "No SameSite=None cookie is missing Secure"),
    );
  }

  results.push(
    !s.sri.externalScripts
      ? info("sri", "No third-party scripts")
      : s.sri.withIntegrity === s.sri.externalScripts
        ? pass("sri", "All third-party scripts have integrity")
        : warn("sri", `${s.sri.withIntegrity} of ${s.sri.externalScripts} third-party scripts have integrity`),
  );
  const insecureForms = s.forms.filter((form) => form.insecure);
  results.push(insecureForms.length ? fail("forms-https", `${insecureForms.length} form${insecureForms.length === 1 ? "" : "s"} post over HTTP`) : pass("forms-https", s.forms.length ? "All forms post over HTTPS" : "No forms to test"));
  // Prefer the richer detector used by the Other information section so the
  // appendix and the report agree. Fall back to the homepage regexes when the
  // crawl files (and therefore the detector) were unavailable.
  const detectedProviders = facts.files?.thirdParties?.providers ?? [];
  const detectedTrackers = detectedProviders
    .filter((provider) =>
      ["advertising", "analytics", "tag-manager", "session-replay"].includes(provider.category),
    )
    .map((provider) => provider.name);
  const trackers = [...new Set(detectedTrackers.length ? detectedTrackers : s.trackers)];
  const consentTools = [
    ...new Set([...(facts.files?.thirdParties?.consent ?? []), ...s.consent]),
  ];
  results.push(trackers.length ? info("trackers", trackers.join(", ")) : pass("trackers", "No third-party trackers detected"));
  results.push(
    trackers.length && !consentTools.length
      ? warn("consent", "Trackers are present but no consent tool was detected")
      : consentTools.length
        ? pass("consent", consentTools.join(", "))
        : pass("consent", "No trackers requiring consent detected"),
  );

  results.push(s.legal.privacy ? pass("privacy-page", "Privacy notice found") : fail("privacy-page", "No privacy notice found"));
  results.push(s.legal.cookies ? pass("cookie-page", "Cookie notice found") : warn("cookie-page", "No cookie notice found"));
  results.push(s.legal.terms ? pass("terms-page", "Terms found") : info("terms-page", "No terms page found"));
  results.push(s.legal.accessibility ? pass("accessibility-page", "Accessibility statement found") : info("accessibility-page", "No accessibility statement found"));

  const e = d?.email;
  const spf = e?.spf;
  const dmarc = e?.dmarc;
  results.push(
    !spf?.present
      ? fail("spf", "No SPF record")
      : spf.qualifier === "-"
        ? pass("spf", "SPF ends with -all")
        : spf.qualifier === "~"
          ? pass("spf", "SPF ends with ~all")
          : warn("spf", `SPF ends with ${spf.qualifier || "no explicit all"}all`),
  );
  results.push(
    !spf?.present
      ? skip("spf-records", "No SPF record")
      : spf.records.length === 1
        ? pass("spf-records", "Exactly one SPF record")
        : fail("spf-records", `${spf.records.length} SPF records; receivers may return permerror`),
  );
  const voidLookups = spf?.voidLookups ?? 0;
  const voidNote = voidLookups ? ` · ${voidLookups} void` : "";
  results.push(
    !spf?.present
      ? skip("spf-lookups", "No SPF record")
      : voidLookups > 2
        ? fail(
            "spf-lookups",
            `${spf.lookupCount} DNS lookups, ${voidLookups} void (void limit 2)`,
          )
        : spf.lookupCount > 10
          ? fail("spf-lookups", `${spf.lookupCount} DNS lookups (limit 10)${voidNote}`)
          : spf.lookupCount > 8
            ? warn("spf-lookups", `${spf.lookupCount} DNS lookups; 10 is the limit${voidNote}`)
            : pass("spf-lookups", `${spf.lookupCount} DNS lookups${voidNote}`),
  );

  results.push(e?.dkimSelectors.length ? pass("dkim", `Selectors: ${e.dkimSelectors.join(", ")}`) : e?.dkimKeys.length ? info("dkim", "Only revoked keys (p= empty); the domain may not send mail") : warn("dkim", "No common DKIM selector found"));
  const dkimKeys = e?.dkimKeys ?? [];
  const revokedKeys = dkimKeys.filter((key) => key.revoked);
  const weakKeys = dkimKeys.filter((key) => key.bits !== null && key.bits < 1024);
  const shortKeys = dkimKeys.filter((key) => key.bits !== null && key.bits >= 1024 && key.bits < 2048);
  const sha1Keys = dkimKeys.filter(
    (key) => key.hashAlgorithms.length > 0 && !key.hashAlgorithms.includes("sha256"),
  );
  results.push(
    !dkimKeys.length
      ? skip("dkim-key", "No DKIM key found")
      : revokedKeys.length === dkimKeys.length
        ? warn("dkim-key", `All ${dkimKeys.length} key${dkimKeys.length === 1 ? " is" : "s are"} revoked (p= empty)`)
        : revokedKeys.length
          ? warn("dkim-key", `${revokedKeys.length} revoked key${revokedKeys.length === 1 ? "" : "s"} (p= empty)`)
          : weakKeys.length
            ? fail("dkim-key", `${weakKeys.length} key${weakKeys.length === 1 ? "" : "s"} below 1024 bits`)
            : shortKeys.length
              ? warn("dkim-key", `${shortKeys.length} key${shortKeys.length === 1 ? "" : "s"} below 2048 bits`)
              : sha1Keys.length
                ? warn("dkim-key", `${sha1Keys.length} key${sha1Keys.length === 1 ? "" : "s"} only advertise SHA-1`)
                : pass("dkim-key", dkimKeys.map((key) => `${key.selector} ${key.bits ?? "?"}-bit`).join(", ")),
  );

  const dmarcTags = [
    dmarc?.adkim ? `adkim=${dmarc.adkim}` : "",
    dmarc?.aspf ? `aspf=${dmarc.aspf}` : "",
    dmarc?.psd ? `psd=${dmarc.psd}` : "",
  ].filter(Boolean);
  results.push(
    !dmarc?.present
      ? fail("dmarc", "No DMARC record")
      : dmarc.policy === "reject" || dmarc.policy === "quarantine"
        ? pass(
            "dmarc",
            `p=${dmarc.policy}${dmarcTags.length ? ` · ${dmarcTags.join(" · ")}` : ""}`,
          )
        : warn("dmarc", `p=${dmarc.policy || "none"}`),
  );
  results.push(
    !dmarc?.present
      ? skip("dmarc-reporting", "No DMARC record")
      : dmarc.rua
        ? pass(
            "dmarc-reporting",
            `${dmarc.rua}${dmarc.fo ? ` · fo=${dmarc.fo}` : ""}${dmarc.ruf ? " · ruf set" : ""}`,
          )
        : warn("dmarc-reporting", "No rua= aggregate report address"),
  );
  results.push(
    !dmarc?.present
      ? skip("dmarc-testing", "No DMARC record")
      : dmarc.testing
        ? dmarc.policy === "reject" || dmarc.policy === "quarantine"
          ? warn("dmarc-testing", "t=y: the policy is applied one level lower")
          : info("dmarc-testing", "t=y has no effect on p=none")
        : dmarc.policy === "reject" || dmarc.policy === "quarantine"
          ? pass("dmarc-testing", "Policy is enforced")
          : info("dmarc-testing", `p=${dmarc.policy || "none"} does not enforce a policy`),
  );
  const subdomainPolicy = dmarc?.subdomainPolicy || dmarc?.policy || "none";
  const nonExistentPolicy = dmarc?.nonExistentPolicy || subdomainPolicy;
  const enforcing = (policy: string) => policy === "reject" || policy === "quarantine";
  results.push(
    !dmarc?.present
      ? skip("dmarc-subdomains", "No DMARC record")
      : enforcing(subdomainPolicy) && enforcing(nonExistentPolicy)
        ? pass("dmarc-subdomains", `effective sp=${subdomainPolicy}, np=${nonExistentPolicy}`)
        : warn("dmarc-subdomains", `effective sp=${subdomainPolicy}, np=${nonExistentPolicy}`),
  );
  results.push(
    !dmarc?.present
      ? skip("dmarc-obsolete-tags", "No DMARC record")
      : dmarc.pct !== null
        ? info("dmarc-obsolete-tags", `pct=${dmarc.pct} is historic in RFC 9989; use t=y|n`)
        : pass("dmarc-obsolete-tags", "No historic pct tag"),
  );
  results.push(
    !dmarc?.present || !dmarc.externalReporting.length
      ? skip("dmarc-external-report", dmarc?.rua ? "No external report domain" : "No rua= address")
      : dmarc.externalReporting.every((entry) => entry.authorized)
        ? pass("dmarc-external-report", `${dmarc.externalReporting.length} external report domain${dmarc.externalReporting.length === 1 ? "" : "s"} authorised`)
        : warn(
            "dmarc-external-report",
            `${dmarc.externalReporting.filter((entry) => !entry.authorized).length} external report domain${dmarc.externalReporting.filter((entry) => !entry.authorized).length === 1 ? "" : "s"} not authorised`,
            dmarc.externalReporting
              .filter((entry) => !entry.authorized)
              .map((entry) => `${entry.target}: ${entry.record || "no authorisation record"}`)
              .join("\n"),
          ),
  );

  results.push(e?.bimi ? pass("bimi", "BIMI record present") : info("bimi", "No BIMI record"));
  results.push(
    !e?.bimi
      ? info("bimi-assets", "No BIMI record")
      : !e.bimiLogo
        ? warn("bimi-assets", "BIMI record has no l= logo")
        : !/^https:\/\//i.test(e.bimiLogo)
          ? fail("bimi-assets", `Logo is not HTTPS: ${e.bimiLogo}`)
          : e.bimiAuthority && !/^https:\/\//i.test(e.bimiAuthority)
            ? warn("bimi-assets", `Authority is not HTTPS: ${e.bimiAuthority}`)
            : pass("bimi-assets", e.bimiAuthority ? "Logo and authority are HTTPS" : "Logo is HTTPS; no authority (VMC)"),
  );

  results.push(e?.mtaSts ? pass("mta-sts-dns", "_mta-sts TXT present") : warn("mta-sts-dns", "No _mta-sts TXT record"));
  const mtaSts = facts.transport?.mtaSts ?? null;
  results.push(
    !e?.mtaSts && !mtaSts?.present
      ? info("mta-sts-policy", "No MTA-STS policy")
      : !mtaSts
        ? fail("mta-sts-policy", "_mta-sts TXT exists but the policy could not be fetched")
        : !mtaSts.present
          ? warn("mta-sts-policy", mtaSts.error || `Policy returned ${mtaSts.status}`)
          : mtaSts.mode !== "enforce"
            ? warn("mta-sts-policy", `mode=${mtaSts.mode || "missing"}`)
            : mtaSts.maxAge < 604_800
              ? warn("mta-sts-policy", `max_age=${mtaSts.maxAge}; use at least 604800`)
              : pass("mta-sts-policy", `mode=enforce, max_age=${mtaSts.maxAge}, ${mtaSts.mx.length} MX`),
  );

  results.push(e?.tlsRpt ? pass("tls-rpt", "_smtp._tls TXT present") : info("tls-rpt", "No TLS-RPT record"));
  results.push(
    !e?.tlsRpt
      ? info("tls-rpt-rua", "No TLS-RPT record")
      : e.tlsRptRua
        ? pass("tls-rpt-rua", e.tlsRptRua)
        : warn("tls-rpt-rua", "TLS-RPT record has no rua="),
  );

  const mxRecords = d?.records.mx ?? [];
  const nullMx = mxRecords.some((item) => item.host === "." || item.host === "");
  results.push(
    !mxRecords.length
      ? info("mx-redundancy", "No MX records; the domain likely does not receive email")
      : nullMx
        ? info("mx-redundancy", "Null MX: the domain does not accept email")
        : mxRecords.length >= 2
          ? pass("mx-redundancy", `${mxRecords.length} MX records`)
          : warn("mx-redundancy", "Only one MX record"),
  );

  const signed = Boolean(d?.records.ds && d?.records.dnskey);
  const dane = e?.dane ?? [];
  const daneHosts = dane.filter((entry) => entry.records.length > 0);
  results.push(
    !dane.length || !mxRecords.length
      ? info("dane-tlsa", "No MX records to check")
      : !daneHosts.length
        ? info("dane-tlsa", "No TLSA records")
        : signed
          ? pass("dane-tlsa", `${daneHosts.length} MX host${daneHosts.length === 1 ? "" : "s"} with TLSA`)
          : warn("dane-tlsa", "TLSA records present but DNSSEC is not enabled"),
  );

  results.push(
    d?.records.ds && d?.records.dnskey
      ? pass("dnssec", "DS at the parent and DNSKEY at the zone")
      : d?.records.ad
        ? pass("dnssec", "Resolver reports the AD bit")
        : d?.records.ds && !d?.records.dnskey
          ? fail("dnssec", "DS at the parent but no DNSKEY")
          : d?.records.dnskey && !d?.records.ds
            ? warn("dnssec", "DNSKEY present but no DS at the parent")
            : warn("dnssec", "Zone is not signed with DNSSEC"),
  );
  results.push(d?.records.caa.length ? pass("caa", `${d.records.caa.length} CAA record${d.records.caa.length === 1 ? "" : "s"}`) : warn("caa", "No CAA records"));
  const caaIssue = (d?.records.caa ?? []).filter((entry) => /^(issue|issuewild)$/i.test(entry.tag));
  results.push(
    !d?.records.caa.length
      ? skip("caa-issue", "No CAA records")
      : caaIssue.length
        ? pass("caa-issue", `${caaIssue.length} issue/issuewild tag${caaIssue.length === 1 ? "" : "s"}`)
        : warn("caa-issue", "CAA exists but has no issue/issuewild tag"),
  );

  const statuses = d?.rdap?.statuses ?? [];
  const isUk = /\.uk$/i.test(facts.domain);
  results.push(
    !d?.rdap
      ? skip("registrar-lock", "Registry data unavailable")
      : isUk
        ? skip("registrar-lock", "Nominet does not publish a transfer-lock status in RDAP")
        : statuses.length === 0
          ? skip("registrar-lock", "The registry did not return status values")
          : statuses.some((status) => /clientTransferProhibited/i.test(status))
            ? pass("registrar-lock", "clientTransferProhibited is set")
            : warn("registrar-lock", "Transfer lock not detected"),
  );
  const expires = d?.rdap?.expires ? new Date(d.rdap.expires).valueOf() : 0;
  const days = expires ? Math.round((expires - Date.now()) / 86_400_000) : 0;
  results.push(
    !expires
      ? skip("registrar-expiry", "Registry data unavailable")
      : days < 0
        ? fail("registrar-expiry", "Domain has expired")
        : days < 30
          ? fail("registrar-expiry", `${days} days remaining`)
          : days < 60
            ? warn("registrar-expiry", `${days} days remaining`)
            : pass("registrar-expiry", `${days} days remaining`),
  );

  const disclosure = `${s.serverDisclosure.server} ${s.serverDisclosure.poweredBy}`.trim();
  results.push(/\d+\.\d+/.test(disclosure) ? warn("server-disclosure", disclosure) : pass("server-disclosure", disclosure || "No version disclosure"));

  return results;
}

/* ------------------------------------------------------------------ */
/* Performance                                                        */
/* ------------------------------------------------------------------ */

export function performanceChecks(facts: AuditFacts): CheckResult[] {
  const p = facts.performance;
  if (!p) {
    return ["ttfb", "html-size", "compression", "render-blocking", "asset-weight", "image-formats", "font-display", "third-parties", "dom-size", "caching", "html-cache-control", "cdn", "broken-images", "psi-performance", "psi-accessibility", "psi-best-practices", "psi-seo", "cwv-lcp", "cwv-cls", "cwv-inp"].map((key) => skip(key, "Performance checks could not run"));
  }

  const results: CheckResult[] = [];
  results.push(p.ttfbMs < 500 ? pass("ttfb", `${p.ttfbMs} ms`) : p.ttfbMs < 1000 ? warn("ttfb", `${p.ttfbMs} ms`) : fail("ttfb", `${p.ttfbMs} ms`));
  results.push(p.htmlBytes < 100_000 ? pass("html-size", `${Math.round(p.htmlBytes / 1024)} KB`) : p.htmlBytes < 200_000 ? warn("html-size", `${Math.round(p.htmlBytes / 1024)} KB`) : fail("html-size", `${Math.round(p.htmlBytes / 1024)} KB`));
  results.push(/br|gzip|deflate|zstd/i.test(p.contentEncoding) ? pass("compression", p.contentEncoding) : warn("compression", p.contentEncoding || "No compression"));
  results.push(p.renderBlocking <= 3 ? pass("render-blocking", `${p.renderBlocking} blocking asset${p.renderBlocking === 1 ? "" : "s"}`) : p.renderBlocking <= 6 ? warn("render-blocking", `${p.renderBlocking} blocking assets`) : fail("render-blocking", `${p.renderBlocking} blocking assets`));
  results.push(
    !p.assetBytes
      ? skip("asset-weight", "Asset sizes unavailable")
      : p.assetBytes < 2_000_000
        ? pass("asset-weight", `${(p.assetBytes / 1024 / 1024).toFixed(1)} MB sampled`)
        : p.assetBytes < 4_000_000
          ? warn("asset-weight", `${(p.assetBytes / 1024 / 1024).toFixed(1)} MB sampled`)
          : fail("asset-weight", `${(p.assetBytes / 1024 / 1024).toFixed(1)} MB sampled`),
  );
  const imageTotal = Object.values(p.imageFormats).reduce((total, value) => total + value, 0);
  const modern = (p.imageFormats.AVIF ?? 0) + (p.imageFormats.WebP ?? 0);
  results.push(
    !imageTotal
      ? info("image-formats", "No images on the homepage")
      : modern / imageTotal >= 0.5
        ? pass("image-formats", `${modern} of ${imageTotal} images use AVIF/WebP`)
        : modern > 0
          ? warn("image-formats", `${modern} of ${imageTotal} images use AVIF/WebP`)
          : fail("image-formats", `No AVIF/WebP among ${imageTotal} images`),
  );
  results.push(
    p.fontDisplay === "swap" || p.fontDisplay === "optional" || p.fontDisplay === "fallback"
      ? pass("font-display", p.fontDisplay)
      : p.fontDisplay === "block" || p.fontDisplay === "not set"
        ? fail("font-display", p.fontDisplay)
        : info("font-display", p.fontDisplay),
  );
  // Use the same sampled set as Other information when it is available, so the
  // scored count and the inventory do not tell different stories.
  const thirdPartyDomains =
    facts.files?.thirdParties?.domains.length ?? p.thirdPartyDomains.length;
  results.push(thirdPartyDomains <= 3 ? pass("third-parties", `${thirdPartyDomains} third-party domain${thirdPartyDomains === 1 ? "" : "s"}`) : thirdPartyDomains <= 8 ? warn("third-parties", `${thirdPartyDomains} third-party domains`) : fail("third-parties", `${thirdPartyDomains} third-party domains`));
  results.push(p.domSize < 1500 ? pass("dom-size", `${p.domSize} elements`) : p.domSize < 3000 ? warn("dom-size", `${p.domSize} elements`) : fail("dom-size", `${p.domSize} elements`));
  results.push(/max-age|immutable|public/i.test(p.cacheControl) ? pass("caching", p.cacheControl) : warn("caching", p.cacheControl || "No Cache-Control"));
  const htmlCache = facts.transport?.homepage.headers["cache-control"] ?? "";
  const htmlMaxAge = /max-age\s*=\s*(\d+)/i.exec(htmlCache)?.[1] ?? "";
  results.push(
    !facts.transport
      ? skip("html-cache-control", "Transport data unavailable")
      : !htmlCache
        ? info("html-cache-control", "No Cache-Control on the HTML")
        : /no-store|no-cache/i.test(htmlCache) || htmlMaxAge === "0"
          ? pass("html-cache-control", htmlCache)
          : htmlMaxAge
            ? warn("html-cache-control", `HTML is cached for ${htmlMaxAge}s: ${htmlCache}`)
            : info("html-cache-control", htmlCache),
  );
  results.push(p.cdn !== "None detected" ? pass("cdn", p.cdn) : warn("cdn", "No CDN detected"));
  results.push(p.brokenImages.length ? fail("broken-images", `${p.brokenImages.length} broken image${p.brokenImages.length === 1 ? "" : "s"}`, p.brokenImages.join("\n")) : pass("broken-images", "Sampled images resolve"));

  const psi = p.psi;
  const psiCheck = (key: string, value: number | null | undefined): CheckResult => {
    if (!psi) return skip(key, "PageSpeed Insights not configured");
    if (value === null || value === undefined) return skip(key, psi.error ?? "Not measured");
    return value >= 90 ? pass(key, `${value}/100`) : value >= 50 ? warn(key, `${value}/100`) : fail(key, `${value}/100`);
  };
  results.push(psiCheck("psi-performance", psi?.performance));
  results.push(psiCheck("psi-accessibility", psi?.accessibility));
  results.push(psiCheck("psi-best-practices", psi?.bestPractices));
  results.push(psiCheck("psi-seo", psi?.seo));
  results.push(psi ? cwvCheck("cwv-lcp", psi.lcp, 2500, 4000) : skip("cwv-lcp", "PageSpeed Insights not configured"));
  results.push(psi ? cwvCheck("cwv-cls", psi.cls, 0.1, 0.25) : skip("cwv-cls", "PageSpeed Insights not configured"));
  results.push(psi ? cwvCheck("cwv-inp", psi.inp, 200, 500) : skip("cwv-inp", "PageSpeed Insights not configured"));

  return results;
}

/* ------------------------------------------------------------------ */
/* Migration                                                          */
/* ------------------------------------------------------------------ */

export function migrationChecks(facts: AuditFacts): CheckResult[] {
  const m = facts.migration;
  if (!m) {
    return ["platform", "hosting", "page-count", "ecommerce", "booking", "analytics", "email-provider", "registrar", "domain-expiry", "dns-records", "contacts", "social", "legal-pages", "legacy-tech", "multilingual", "redirect-complexity", "content-inventory"].map((key) => skip(key, "Migration checks could not run"));
  }

  const results: CheckResult[] = [];
  results.push(
    m.platform !== "Unknown / custom" && m.platformConfidence === "high"
      ? pass("platform", m.platform)
      : m.platform !== "Unknown / custom"
        ? warn("platform", `${m.platform} (${m.platformConfidence} confidence)`)
        : info("platform", "No common platform fingerprint found"),
  );
  results.push(m.hosting !== "Unknown" ? pass("hosting", m.hosting) : info("hosting", "Hosting provider not identified"));
  results.push(m.pageCount > 0 ? pass("page-count", `${m.pageCount} URLs in the sitemap`) : warn("page-count", "No sitemap inventory"));
  results.push(m.ecommerce.length ? pass("ecommerce", m.ecommerce.join(", ")) : info("ecommerce", "No commerce signals"));
  results.push(m.booking.length ? pass("booking", m.booking.join(", ")) : info("booking", "No booking signals"));
  results.push(m.analytics.length ? pass("analytics", m.analytics.join(", ")) : info("analytics", "No analytics or tag manager detected"));
  results.push(m.emailProvider !== "No MX records" ? pass("email-provider", m.emailProvider) : fail("email-provider", "No MX records"));
  results.push(m.registrar !== "Unknown" ? pass("registrar", m.registrar) : info("registrar", "Registrar not identified"));

  const expiry = m.domainExpires ? new Date(m.domainExpires).valueOf() : 0;
  const days = expiry ? Math.round((expiry - Date.now()) / 86_400_000) : 0;
  results.push(
    !expiry
      ? skip("domain-expiry", "Registry data unavailable")
      : days < 0
        ? fail("domain-expiry", "Domain has expired")
        : days < 30
          ? fail("domain-expiry", `${days} days remaining`)
          : days < 60
            ? warn("domain-expiry", `${days} days remaining`)
            : pass("domain-expiry", `${days} days remaining`),
  );
  results.push(m.dnsSummary.a + m.dnsSummary.aaaa > 0 ? pass("dns-records", `${m.dnsSummary.a} A, ${m.dnsSummary.aaaa} AAAA, ${m.dnsSummary.mx} MX, ${m.dnsSummary.ns} NS`) : fail("dns-records", "No A or AAAA records"));
  results.push(m.emails.length || m.phones.length ? pass("contacts", [...m.emails, ...m.phones].slice(0, 4).join(", ")) : info("contacts", "No public contact details found"));
  results.push(m.social.length ? pass("social", `${m.social.length} social profile${m.social.length === 1 ? "" : "s"} linked`) : info("social", "No social links found"));
  results.push(
    m.legalPages.includes("Privacy notice") && m.legalPages.length >= 3
      ? pass("legal-pages", m.legalPages.join(", "))
      : m.legalPages.includes("Privacy notice")
        ? warn("legal-pages", m.legalPages.join(", "))
        : fail("legal-pages", "No privacy notice identified"),
  );
  results.push(m.legacy.length ? warn("legacy-tech", m.legacy.join(", ")) : pass("legacy-tech", "No obvious legacy technology"));
  results.push(m.languages.length > 1 ? pass("multilingual", `Languages: ${m.languages.join(", ")}`) : info("multilingual", "Single language"));
  results.push(m.redirectComplexity <= 2 ? pass("redirect-complexity", `${m.redirectComplexity} hops at most`) : m.redirectComplexity <= 4 ? warn("redirect-complexity", `${m.redirectComplexity} hops at most`) : fail("redirect-complexity", `${m.redirectComplexity} hops at most`));
  results.push(m.content.pages > 0 && m.content.words > 0 ? pass("content-inventory", `${m.content.pages} pages, ${m.content.images} images, ${m.content.words} words on the homepage`) : warn("content-inventory", "Content volume could not be measured"));

  return results;
}

export function allChecks(facts: AuditFacts): CheckResult[] {
  return [
    ...transportChecks(facts),
    ...redirectChecks(facts),
    ...metadataChecks(facts),
    ...crawlChecks(facts),
    ...wellknownChecks(facts),
    ...securityChecks(facts),
    ...performanceChecks(facts),
    ...migrationChecks(facts),
  ];
}

export function statusLabel(status: CheckStatus): string {
  return status === "pass" ? "Pass" : status === "warn" ? "Warning" : status === "fail" ? "Fail" : status === "info" ? "Info" : status === "skipped" ? "Not checked" : "Error";
}
