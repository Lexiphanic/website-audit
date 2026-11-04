import type {
  EdgeFact,
  PrivacyLevel,
  ThirdPartyCategory,
  ThirdPartyDomainFact,
  ThirdPartyFacts,
  ThirdPartyProviderFact,
} from "./types";

export interface ThirdPartyPageInput {
  url: string;
  headers?: Record<string, string>;
  htmlSource: string;
  scripts: string[];
  stylesheets: string[];
  images: string[];
  iframes: string[];
  hints: string[];
}

interface Signature {
  name: string;
  category: ThirdPartyCategory;
  privacy: PrivacyLevel;
  /** Hostname suffixes. Omit to match any host when `paths` is set. */
  hosts?: string[];
  paths?: RegExp[];
  inline?: RegExp[];
}

const SIGNATURES: Signature[] = [
  /* Advertising and social pixels */
  {
    name: "Meta Pixel",
    category: "advertising",
    privacy: "high",
    hosts: ["connect.facebook.net", "facebook.com"],
    paths: [/fbevents\.js/i, /^\/tr\/?$/i],
    inline: [/fbq\s*\(/i],
  },
  {
    name: "Google Ads",
    category: "advertising",
    privacy: "high",
    hosts: ["doubleclick.net", "googlesyndication.com", "googleadservices.com"],
  },
  {
    name: "Google Ads",
    category: "advertising",
    privacy: "high",
    hosts: ["google.com"],
    paths: [/^\/pagead\//i, /^\/ads\//i],
  },
  {
    name: "LinkedIn Insight",
    category: "advertising",
    privacy: "high",
    hosts: ["snap.licdn.com", "linkedin.com"],
    paths: [/insight/i, /^\/px\/?$/i],
    inline: [/lintrk\s*\(/i],
  },
  {
    name: "TikTok Pixel",
    category: "advertising",
    privacy: "high",
    hosts: ["analytics.tiktok.com"],
    inline: [/ttq\s*\./i],
  },
  {
    name: "Pinterest Tag",
    category: "advertising",
    privacy: "high",
    hosts: ["ct.pinterest.com"],
    inline: [/pintrk\s*\(/i],
  },
  {
    name: "Snap Pixel",
    category: "advertising",
    privacy: "high",
    hosts: ["sc-static.net", "tr.snapchat.com"],
    inline: [/snaptr\s*\(/i],
  },
  {
    name: "X Pixel",
    category: "advertising",
    privacy: "high",
    hosts: ["static.ads-twitter.com", "analytics.twitter.com"],
    inline: [/twq\s*\(/i],
  },
  {
    name: "Reddit Pixel",
    category: "advertising",
    privacy: "high",
    hosts: ["redditstatic.com", "alb.reddit.com"],
    inline: [/rdt\s*\(/i],
  },
  {
    name: "Quora Pixel",
    category: "advertising",
    privacy: "high",
    hosts: ["q.quora.com"],
  },
  {
    name: "Microsoft Ads",
    category: "advertising",
    privacy: "high",
    hosts: ["bat.bing.com"],
  },
  {
    name: "Microsoft Ads",
    category: "advertising",
    privacy: "high",
    hosts: ["bing.com"],
    paths: [/^\/action\//i],
  },
  {
    name: "Criteo",
    category: "advertising",
    privacy: "high",
    hosts: ["static.criteo.net", "dis.criteo.com"],
  },
  {
    name: "Taboola",
    category: "advertising",
    privacy: "high",
    hosts: ["cdn.taboola.com"],
  },
  {
    name: "Outbrain",
    category: "advertising",
    privacy: "high",
    hosts: ["amplify.outbrain.com"],
  },
  {
    name: "Amazon Ads",
    category: "advertising",
    privacy: "high",
    hosts: ["amazon-adsystem.com"],
  },
  {
    name: "Yandex Metrica",
    category: "advertising",
    privacy: "high",
    hosts: ["mc.yandex.ru", "yandex.ru"],
    paths: [/metrika/i],
    inline: [/ym\s*\(/i],
  },
  {
    name: "Comscore",
    category: "advertising",
    privacy: "high",
    hosts: ["scorecardresearch.com"],
  },
  {
    name: "Quantcast",
    category: "advertising",
    privacy: "high",
    hosts: ["quantserve.com", "quantcast.com"],
  },
  {
    name: "The Trade Desk",
    category: "advertising",
    privacy: "high",
    hosts: ["adsrvr.org"],
  },
  {
    name: "PubMatic",
    category: "advertising",
    privacy: "high",
    hosts: ["pubmatic.com"],
  },
  {
    name: "Magnite",
    category: "advertising",
    privacy: "high",
    hosts: ["rubiconproject.com"],
  },
  {
    name: "OpenX",
    category: "advertising",
    privacy: "high",
    hosts: ["openx.net"],
  },
  {
    name: "Moat",
    category: "advertising",
    privacy: "high",
    hosts: ["moatads.com"],
  },
  {
    name: "Clearbit",
    category: "analytics",
    privacy: "high",
    hosts: ["clearbit.com"],
  },

  /* Analytics and tag managers */
  {
    name: "Google tag (GTM/GA4)",
    category: "tag-manager",
    privacy: "medium",
    hosts: ["googletagmanager.com"],
    inline: [/gtag\s*\(/i, /GTM-[A-Z0-9]+/],
  },
  {
    name: "Google Analytics",
    category: "analytics",
    privacy: "medium",
    hosts: ["google-analytics.com"],
  },
  {
    name: "Segment",
    category: "analytics",
    privacy: "medium",
    hosts: ["cdn.segment.com", "api.segment.io"],
    inline: [/analytics\.load\s*\(/i],
  },
  {
    name: "Mixpanel",
    category: "analytics",
    privacy: "medium",
    hosts: ["cdn.mxpnl.com", "api.mixpanel.com"],
    inline: [/mixpanel\.init/i],
  },
  {
    name: "Amplitude",
    category: "analytics",
    privacy: "medium",
    hosts: ["cdn.amplitude.com", "api.amplitude.com"],
    inline: [/amplitude\.getInstance/i],
  },
  {
    name: "PostHog",
    category: "analytics",
    privacy: "medium",
    hosts: ["posthog.com", "i.posthog.com"],
    inline: [/posthog\.init/i],
  },
  {
    name: "Heap",
    category: "analytics",
    privacy: "medium",
    hosts: ["heapanalytics.com"],
    inline: [/heap\.load/i],
  },
  {
    name: "Plausible",
    category: "analytics",
    privacy: "medium",
    hosts: ["plausible.io"],
    inline: [/plausible\s*\(/i],
  },
  {
    name: "Fathom",
    category: "analytics",
    privacy: "medium",
    hosts: ["usefathom.com", "cdn.usefathom.com"],
  },
  {
    name: "Matomo",
    category: "analytics",
    privacy: "medium",
    paths: [/matomo\.js/i, /piwik\.js/i],
    inline: [/_paq/],
  },
  {
    name: "Adobe Analytics",
    category: "analytics",
    privacy: "medium",
    hosts: ["omtrdc.net", "2o7.net"],
  },
  {
    name: "Adobe Launch",
    category: "tag-manager",
    privacy: "medium",
    hosts: ["adobedtm.com"],
  },
  {
    name: "HubSpot",
    category: "analytics",
    privacy: "medium",
    hosts: ["hs-scripts.com", "hs-analytics.net"],
    inline: [/_hsq/],
  },
  {
    name: "Marketo",
    category: "analytics",
    privacy: "medium",
    hosts: ["munchkin.marketo.net"],
    inline: [/Munchkin\.init/i],
  },
  {
    name: "Pardot",
    category: "analytics",
    privacy: "medium",
    hosts: ["pi.pardot.com"],
  },

  /* Session replay */
  {
    name: "Hotjar",
    category: "session-replay",
    privacy: "high",
    hosts: ["static.hotjar.com", "script.hotjar.com"],
    inline: [/hj\s*\(/i],
  },
  {
    name: "Microsoft Clarity",
    category: "session-replay",
    privacy: "high",
    hosts: ["clarity.ms"],
    inline: [/clarity\s*\(/i],
  },
  {
    name: "FullStory",
    category: "session-replay",
    privacy: "high",
    hosts: ["fullstory.com"],
    inline: [/FS\.identify/i],
  },
  {
    name: "LogRocket",
    category: "session-replay",
    privacy: "high",
    hosts: ["logrocket.com"],
    inline: [/LogRocket\.init/i],
  },
  {
    name: "Contentsquare",
    category: "session-replay",
    privacy: "high",
    hosts: ["contentsquare.net"],
  },

  /* Consent */
  {
    name: "OneTrust",
    category: "consent",
    privacy: "low",
    hosts: ["onetrust.com", "cookielaw.org"],
    inline: [/OneTrust|Optanon/i],
  },
  {
    name: "Cookiebot",
    category: "consent",
    privacy: "low",
    hosts: ["cookiebot.com"],
    inline: [/Cookiebot/i],
  },
  {
    name: "CookieYes",
    category: "consent",
    privacy: "low",
    hosts: ["cookieyes.com"],
  },
  {
    name: "Borlabs Cookie",
    category: "consent",
    privacy: "low",
    paths: [/borlabs/i],
    inline: [/borlabs/i],
  },
  {
    name: "Cookie consent script",
    category: "consent",
    privacy: "low",
    paths: [/(?:cookieconsent|gdpr-cookie)/i],
    inline: [/(?:cookieconsent|gdpr-cookie)/i],
  },
  {
    name: "Osano",
    category: "consent",
    privacy: "low",
    hosts: ["osano.com"],
  },
  {
    name: "Termly",
    category: "consent",
    privacy: "low",
    hosts: ["termly.io"],
  },
  {
    name: "iubenda",
    category: "consent",
    privacy: "low",
    hosts: ["iubenda.com"],
  },
  {
    name: "Complianz",
    category: "consent",
    privacy: "low",
    hosts: ["complianz.io"],
  },
  {
    name: "Usercentrics",
    category: "consent",
    privacy: "low",
    hosts: ["usercentrics.eu"],
  },
  {
    name: "Didomi",
    category: "consent",
    privacy: "low",
    hosts: ["didomi.io"],
  },
  {
    name: "Sourcepoint",
    category: "consent",
    privacy: "low",
    hosts: ["sourcepoint.com"],
  },

  /* Chat and support */
  {
    name: "Intercom",
    category: "functional",
    privacy: "medium",
    hosts: ["intercom.io", "intercomcdn.com"],
    inline: [/Intercom\s*\(/i],
  },
  {
    name: "Drift",
    category: "functional",
    privacy: "medium",
    hosts: ["driftt.com"],
    inline: [/drift\.load/i],
  },
  {
    name: "Crisp",
    category: "functional",
    privacy: "medium",
    hosts: ["crisp.chat"],
  },
  {
    name: "Tawk.to",
    category: "functional",
    privacy: "medium",
    hosts: ["embed.tawk.to"],
  },
  {
    name: "Zendesk",
    category: "functional",
    privacy: "medium",
    hosts: ["zdassets.com", "zendesk.com"],
    paths: [/embeddable/i],
  },
  {
    name: "LiveChat",
    category: "functional",
    privacy: "medium",
    hosts: ["livechatinc.com"],
  },

  /* Embeds and functional third parties */
  {
    name: "YouTube",
    category: "embedded",
    privacy: "medium",
    hosts: ["youtube.com", "youtube-nocookie.com"],
    paths: [/^\/embed\//i],
  },
  {
    name: "Vimeo",
    category: "embedded",
    privacy: "medium",
    hosts: ["player.vimeo.com"],
  },
  {
    name: "Instagram",
    category: "social",
    privacy: "medium",
    hosts: ["instagram.com"],
    paths: [/^\/embed/i],
  },
  {
    name: "Facebook Embed",
    category: "social",
    privacy: "medium",
    hosts: ["facebook.com"],
    paths: [/^\/plugins\//i],
  },
  {
    name: "X Embed",
    category: "social",
    privacy: "medium",
    hosts: ["platform.twitter.com"],
  },
  {
    name: "TikTok Embed",
    category: "social",
    privacy: "medium",
    hosts: ["tiktok.com"],
    paths: [/^\/embed/i],
  },
  {
    name: "Spotify Embed",
    category: "embedded",
    privacy: "medium",
    hosts: ["open.spotify.com"],
    paths: [/^\/embed/i],
  },
  {
    name: "SoundCloud Embed",
    category: "embedded",
    privacy: "medium",
    hosts: ["w.soundcloud.com"],
    paths: [/\/player/i],
  },
  {
    name: "Google Maps",
    category: "embedded",
    privacy: "medium",
    hosts: ["google.com", "maps.google.com"],
    paths: [/maps\/embed/i],
  },
  {
    name: "reCAPTCHA",
    category: "functional",
    privacy: "low",
    hosts: ["google.com", "gstatic.com"],
    paths: [/recaptcha/i],
  },
  {
    name: "hCaptcha",
    category: "functional",
    privacy: "low",
    hosts: ["hcaptcha.com"],
  },
  {
    name: "Cloudflare Turnstile",
    category: "functional",
    privacy: "low",
    hosts: ["challenges.cloudflare.com"],
  },
];

const PRIVACY_ORDER: Record<PrivacyLevel, number> = { high: 0, medium: 1, low: 2 };

function stripWww(host: string): string {
  return host.replace(/^www\./i, "").toLowerCase();
}

function hostMatches(host: string, suffixes: string[]): boolean {
  const clean = stripWww(host);
  return suffixes.some((suffix) => {
    const value = suffix.toLowerCase();
    return clean === value || clean.endsWith(`.${value}`);
  });
}

function matchSignature(signature: Signature, url: URL): boolean {
  if (signature.hosts && !hostMatches(url.hostname, signature.hosts)) return false;
  if (!signature.hosts && !signature.paths) return false;
  if (signature.paths && !signature.paths.some((pattern) => pattern.test(url.pathname))) {
    return false;
  }
  return true;
}

function absolute(value: string, base: string): URL | null {
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

function evidenceFor(
  source: "script" | "stylesheet" | "image" | "iframe" | "hint",
  url: URL,
): string {
  const value = `${url.hostname}${url.pathname}`.slice(0, 120);
  return `${source}: ${value}`;
}

export function emptyThirdPartyFacts(): ThirdPartyFacts {
  return { edge: null, dns: null, providers: [], domains: [], consent: [] };
}

/** Detect known tracking, consent, chat and embed providers in one page. */
export function detectThirdParties(input: ThirdPartyPageInput): ThirdPartyFacts {
  const pageUrl = absolute(input.url, input.url);
  if (!pageUrl) return emptyThirdPartyFacts();

  const resources: { url: URL; source: "script" | "stylesheet" | "image" | "iframe" | "hint" }[] = [];
  const add = (
    values: string[],
    source: "script" | "stylesheet" | "image" | "iframe" | "hint",
  ) => {
    for (const value of values) {
      const url = absolute(value, pageUrl.href);
      if (url && /^https?:$/.test(url.protocol)) resources.push({ url, source });
    }
  };
  add(input.scripts, "script");
  add(input.stylesheets, "stylesheet");
  add(input.images, "image");
  add(input.iframes, "iframe");
  add(input.hints, "hint");

  const providers = new Map<string, ThirdPartyProviderFact>();
  const domains = new Map<string, { count: number; categories: Set<ThirdPartyCategory> }>();
  const pageHost = stripWww(pageUrl.hostname);

  const addProvider = (
    signature: Signature,
    evidence: string,
    source: ThirdPartyProviderFact["source"],
  ) => {
    const existing = providers.get(signature.name);
    if (existing) {
      if (!existing.evidence.includes(evidence) && existing.evidence.length < 3) {
        existing.evidence.push(evidence);
      }
      return;
    }
    providers.set(signature.name, {
      name: signature.name,
      category: signature.category,
      privacy: signature.privacy,
      evidence: [evidence],
      source,
    });
  };

  for (const resource of resources) {
    const host = stripWww(resource.url.hostname);
    if (host && host !== pageHost) {
      const entry = domains.get(host) ?? { count: 0, categories: new Set<ThirdPartyCategory>() };
      entry.count += 1;
      domains.set(host, entry);
    }
    for (const signature of SIGNATURES) {
      if (!matchSignature(signature, resource.url)) continue;
      addProvider(signature, evidenceFor(resource.source, resource.url), resource.source);
      const domain = domains.get(host);
      if (domain) domain.categories.add(signature.category);
    }
  }

  for (const signature of SIGNATURES) {
    if (!signature.inline?.some((pattern) => pattern.test(input.htmlSource))) continue;
    addProvider(signature, "inline: page source", "inline");
  }

  const domainFacts: ThirdPartyDomainFact[] = [...domains.entries()]
    .map(([host, entry]) => ({
      host,
      count: entry.count,
      categories: [...entry.categories],
    }))
    .sort((a, b) => b.count - a.count || a.host.localeCompare(b.host))
    .slice(0, 20);

  const providerFacts = [...providers.values()].sort(
    (a, b) => PRIVACY_ORDER[a.privacy] - PRIVACY_ORDER[b.privacy] || a.name.localeCompare(b.name),
  );

  return {
    edge: detectEdge(input.headers ?? {}),
    dns: null,
    providers: providerFacts,
    domains: domainFacts,
    consent: providerFacts.filter((provider) => provider.category === "consent").map((provider) => provider.name),
  };
}

/** Merge homepage and sampled-page findings into one site-level fact. */
export function mergeThirdPartyFacts(
  ...facts: (ThirdPartyFacts | null | undefined)[]
): ThirdPartyFacts {
  const merged = emptyThirdPartyFacts();
  const providers = new Map<string, ThirdPartyProviderFact>();
  const domains = new Map<string, ThirdPartyDomainFact>();
  const consent = new Set<string>();

  for (const fact of facts) {
    if (!fact) continue;
    merged.edge ??= fact.edge;
    merged.dns ??= fact.dns;
    for (const provider of fact.providers) {
      const existing = providers.get(provider.name);
      if (existing) {
        for (const evidence of provider.evidence) {
          if (!existing.evidence.includes(evidence) && existing.evidence.length < 3) {
            existing.evidence.push(evidence);
          }
        }
      } else {
        providers.set(provider.name, { ...provider, evidence: [...provider.evidence] });
      }
    }
    for (const domain of fact.domains) {
      const existing = domains.get(domain.host);
      if (existing) {
        existing.count += domain.count;
        existing.categories = [...new Set([...existing.categories, ...domain.categories])];
      } else {
        domains.set(domain.host, { ...domain, categories: [...domain.categories] });
      }
    }
    for (const name of fact.consent) consent.add(name);
  }

  merged.providers = [...providers.values()].sort(
    (a, b) => PRIVACY_ORDER[a.privacy] - PRIVACY_ORDER[b.privacy] || a.name.localeCompare(b.name),
  );
  merged.domains = [...domains.values()]
    .sort((a, b) => b.count - a.count || a.host.localeCompare(b.host))
    .slice(0, 20);
  merged.consent = [...consent].sort();
  return merged;
}

function headerEvidence(headers: Record<string, string>, keys: string[]): string[] {
  const evidence: string[] = [];
  for (const key of keys) {
    const value = headers[key];
    if (!value) continue;
    evidence.push(`${key}: ${value}`.slice(0, 80));
    if (evidence.length >= 3) break;
  }
  return evidence;
}

/** Identify the edge/CDN from response headers. */
export function detectEdge(headers: Record<string, string>): EdgeFact | null {
  const h: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) h[key.toLowerCase()] = String(value);
  const server = h.server ?? "";
  const via = h.via ?? "";

  if (h["cf-ray"] || h["cf-cache-status"] || /cloudflare/i.test(server)) {
    return { name: "Cloudflare", confidence: "high", evidence: headerEvidence(h, ["cf-ray", "cf-cache-status", "server"]) };
  }
  if (h["x-fastly-request-id"] || h["x-served-by"] || h["fastly-io-info"]) {
    return { name: "Fastly", confidence: "high", evidence: headerEvidence(h, ["x-fastly-request-id", "x-served-by", "fastly-io-info"]) };
  }
  if (h["x-amz-cf-id"] || h["x-amz-cf-pop"] || /cloudfront/i.test(via) || /cloudfront/i.test(h["x-cache"] ?? "")) {
    return { name: "Amazon CloudFront", confidence: "high", evidence: headerEvidence(h, ["x-amz-cf-id", "x-amz-cf-pop", "x-cache", "via"]) };
  }
  if (h["x-akamai-transformed"] || /akamai/i.test(server)) {
    return { name: "Akamai", confidence: "high", evidence: headerEvidence(h, ["x-akamai-transformed", "server"]) };
  }
  if (h["x-vercel-id"] || h["x-vercel-cache"]) {
    return { name: "Vercel", confidence: "high", evidence: headerEvidence(h, ["x-vercel-id", "x-vercel-cache"]) };
  }
  if (h["x-nf-request-id"] || /netlify/i.test(server)) {
    return { name: "Netlify", confidence: "high", evidence: headerEvidence(h, ["x-nf-request-id", "server"]) };
  }
  if (h["x-github-request-id"] || /github/i.test(server)) {
    return { name: "GitHub", confidence: "high", evidence: headerEvidence(h, ["x-github-request-id", "server"]) };
  }
  if (h["x-azure-ref"] || h["x-fd-int-roxy-purgeid"]) {
    return { name: "Azure Front Door", confidence: "high", evidence: headerEvidence(h, ["x-azure-ref", "x-fd-int-roxy-purgeid"]) };
  }
  if (/^1\.1 google$/i.test(via) || /google frontend/i.test(server)) {
    return { name: "Google Cloud CDN", confidence: "medium", evidence: headerEvidence(h, ["via", "server"]) };
  }
  if (/bunny/i.test(server)) {
    return { name: "Bunny CDN", confidence: "high", evidence: headerEvidence(h, ["server"]) };
  }
  if (/keycdn/i.test(server)) {
    return { name: "KeyCDN", confidence: "high", evidence: headerEvidence(h, ["server"]) };
  }
  if (h["x-iinfo"] || /incapsula/i.test(h["x-cdn"] ?? "")) {
    return { name: "Imperva", confidence: "high", evidence: headerEvidence(h, ["x-iinfo", "x-cdn"]) };
  }
  if (h["x-sucuri-id"] || /sucuri/i.test(server)) {
    return { name: "Sucuri", confidence: "high", evidence: headerEvidence(h, ["x-sucuri-id", "server"]) };
  }
  if (h["x-llid"] || /ecacc/i.test(server)) {
    return { name: "Edgio", confidence: "high", evidence: headerEvidence(h, ["x-llid", "server"]) };
  }
  if (/cachefly/i.test(server)) {
    return { name: "CacheFly", confidence: "high", evidence: headerEvidence(h, ["server"]) };
  }
  if (h["x-section"]) {
    return { name: "Section", confidence: "high", evidence: headerEvidence(h, ["x-section"]) };
  }
  if (h["x-hw"] || /netdna/i.test(server)) {
    return { name: "StackPath", confidence: "high", evidence: headerEvidence(h, ["x-hw", "server"]) };
  }
  return null;
}

/** Identify the DNS provider from NS records, separately from the edge. */
export function detectDnsProvider(nameservers: string[]): EdgeFact | null {
  const joined = nameservers.join(" ").toLowerCase();
  if (!joined) return null;
  const evidence = nameservers.slice(0, 3);
  const match = (name: string, patterns: RegExp[]): EdgeFact | null =>
    patterns.some((pattern) => pattern.test(joined))
      ? { name, confidence: "high", evidence }
      : null;

  return (
    match("Cloudflare", [/cloudflare\.com/]) ??
    match("Amazon Route 53", [/awsdns/]) ??
    match("Google Cloud DNS", [/googledomains|google\.com/]) ??
    match("Azure DNS", [/azure-dns/]) ??
    match("GoDaddy", [/domaincontrol/]) ??
    match("IONOS", [/ui-dns|ionos/]) ??
    match("123-reg", [/123-reg/]) ??
    match("Krystal", [/krystal/]) ??
    match("Namesco", [/names\.co\.uk/]) ??
    match("Gandi", [/gandi\.net/]) ??
    match("NS1", [/nsone\.net/]) ??
    match("DigitalOcean", [/digitalocean\.com/]) ??
    match("Linode", [/linode\.com/]) ??
    match("Vercel", [/vercel-dns\.com/]) ??
    match("Netlify", [/netlify\.com/]) ??
    match("Bunny", [/bunny\.net/]) ??
    match("DNSimple", [/dnsimple\.com/]) ??
    match("Hurricane Electric", [/he\.net/]) ??
    null
  );
}
