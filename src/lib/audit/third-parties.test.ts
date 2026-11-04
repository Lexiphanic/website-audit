import { describe, expect, test } from "bun:test";
import {
  detectDnsProvider,
  detectEdge,
  detectThirdParties,
  mergeThirdPartyFacts,
} from "./third-parties";

const page = {
  url: "https://example.com/page/",
  headers: { "cf-ray": "abc123", server: "cloudflare" },
  htmlSource: `<!doctype html><html><head>
    <script src="https://www.googletagmanager.com/gtag/js?id=G-TEST"></script>
    <script>function gtag(){}</script>
    <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
    <script>fbq('init','1')</script>
    <script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>
  </head><body>
    <img src="https://www.facebook.com/tr?id=1">
    <iframe src="https://www.youtube.com/embed/abc"></iframe>
  </body></html>`,
  scripts: [
    "https://www.googletagmanager.com/gtag/js?id=G-TEST",
    "https://connect.facebook.net/en_US/fbevents.js",
    "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js",
  ],
  stylesheets: [],
  images: ["https://www.facebook.com/tr?id=1", "https://example.com/photo.jpg"],
  iframes: ["https://www.youtube.com/embed/abc"],
  hints: ["https://fonts.gstatic.com"],
};

describe("detectThirdParties", () => {
  test("detects known providers, including query-string pixels", () => {
    const facts = detectThirdParties(page);
    const names = facts.providers.map((provider) => provider.name);
    expect(names).toContain("Google tag (GTM/GA4)");
    expect(names).toContain("Meta Pixel");
    expect(names).toContain("OneTrust");
    expect(names).toContain("YouTube");
    expect(facts.consent).toContain("OneTrust");
    expect(facts.domains.some((domain) => domain.host === "facebook.com")).toBe(true);
    expect(facts.domains.some((domain) => domain.host === "example.com")).toBe(false);
  });

  test("detects edge and DNS fingerprints", () => {
    expect(detectEdge({ "cf-ray": "abc", server: "cloudflare" })?.name).toBe("Cloudflare");
    expect(detectEdge({ server: "AmazonS3" })).toBeNull();
    expect(detectDnsProvider(["ada.ns.cloudflare.com"])?.name).toBe("Cloudflare");
    expect(detectDnsProvider(["ns1.example.net"])).toBeNull();
  });

  test("merges homepage and sampled-page findings", () => {
    const merged = mergeThirdPartyFacts(
      detectThirdParties(page),
      detectThirdParties({
        ...page,
        url: "https://example.com/two/",
        htmlSource: `<script src="https://analytics.tiktok.com/i18n/pixel/events.js"></script>`,
        scripts: ["https://analytics.tiktok.com/i18n/pixel/events.js"],
        images: [],
        iframes: [],
        hints: [],
      }),
    );
    const names = merged.providers.map((provider) => provider.name);
    expect(names).toContain("Meta Pixel");
    expect(names).toContain("TikTok Pixel");
    expect(merged.domains.find((domain) => domain.host === "facebook.com")?.count).toBe(1);
  });
});
