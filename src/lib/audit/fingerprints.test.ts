import { describe, expect, test } from "bun:test";
import { detectFingerprints } from "./fingerprints";

function names(html: string, headers: Record<string, string> = {}): string[] {
  return detectFingerprints({ html, headers, url: "https://example.com/" }).map((item) => item.name);
}

describe("detectFingerprints", () => {
  test("detects WordPress from asset paths", () => {
    expect(names('<link href="/wp-content/themes/site/style.css">')).toContain("WordPress");
  });

  test("does not treat an ordinary mention as WordPress", () => {
    expect(names("<p>We love WordPress.</p>")).not.toContain("WordPress");
  });

  test("detects Next.js and Stripe", () => {
    const detected = names('<script id="__NEXT_DATA__"></script><script src="https://js.stripe.com/v3/"></script>');
    expect(detected).toContain("Next.js");
    expect(detected).toContain("Stripe");
  });

  test("detects consent tools and Cloudflare headers", () => {
    const detected = names("<script src=\"https://cdn.cookielaw.org/scripttemplates/otSDKStub.js\"></script>", {
      "cf-ray": "abc-LHR",
    });
    expect(detected).toContain("OneTrust");
    expect(detected).toContain("Cloudflare");
  });

  test("detects Astro from the built asset path", () => {
    expect(names('<link rel="stylesheet" href="/_astro/index.abc123.css">')).toContain("Astro");
  });
});
