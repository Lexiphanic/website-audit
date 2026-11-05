import { describe, expect, test } from "bun:test";
import { FINGERPRINT_NAMES } from "./fingerprints";
import { technologyUrl } from "./technology-links";

describe("technologyUrl", () => {
  test("links a detected technology to its vendor", () => {
    expect(technologyUrl("Google Tag Manager")).toBe("https://tagmanager.google.com/");
    expect(technologyUrl("HubSpot CMS")).toBe("https://www.hubspot.com/products/cms");
  });

  test("returns nothing for a name that is not a fingerprint", () => {
    expect(technologyUrl("Unknown / custom")).toBeUndefined();
  });

  test("covers every fingerprint rule", () => {
    const missing = FINGERPRINT_NAMES.filter((name) => !technologyUrl(name));
    expect(missing).toEqual([]);
  });
});
