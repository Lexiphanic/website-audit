import { describe, expect, test } from "bun:test";
import { domainFromParam, normalizeTarget } from "./normalize";

describe("normalizeTarget", () => {
  test("normalises a www URL to the registrable domain", () => {
    const target = normalizeTarget("https://www.Example.com/path?q=1");
    expect(target.domain).toBe("example.com");
    expect(target.host).toBe("example.com");
    expect(target.origin).toBe("https://example.com");
  });

  test("accepts a bare domain", () => {
    expect(normalizeTarget("example.co.uk").domain).toBe("example.co.uk");
  });

  test("keeps a subdomain as the host but uses the registrable domain", () => {
    const target = normalizeTarget("blog.example.com");
    expect(target.domain).toBe("example.com");
    expect(target.host).toBe("blog.example.com");
  });

  test("rejects IP literals, private hosts and unusual ports", () => {
    expect(() => normalizeTarget("http://127.0.0.1")).toThrow();
    expect(() => normalizeTarget("localhost")).toThrow();
    expect(() => normalizeTarget("https://example.com:8443")).toThrow();
    expect(() => normalizeTarget("ftp://example.com")).toThrow();
  });
});

describe("domainFromParam", () => {
  test("strips www", () => {
    expect(domainFromParam("www.example.co.uk")).toBe("example.co.uk");
  });
});
