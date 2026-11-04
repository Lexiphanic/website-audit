import { describe, expect, test } from "bun:test";
import { isPresentFile } from "./files";

describe("isPresentFile", () => {
  test("accepts a real 2xx response", () => {
    expect(isPresentFile({ path: "/llms.txt", status: 200, contentType: "text/plain", bytes: 10, soft404: false })).toBe(true);
  });

  test("rejects 404 and other non-2xx responses", () => {
    expect(isPresentFile({ path: "/llms.txt", status: 404, contentType: "text/html", bytes: 236, soft404: false })).toBe(false);
    expect(isPresentFile({ path: "/llms.txt", status: 301, contentType: "text/html", bytes: 0, soft404: false })).toBe(false);
  });

  test("rejects a 200 that is a themed 404 page", () => {
    expect(isPresentFile({ path: "/llms.txt", status: 200, contentType: "text/html", bytes: 500, soft404: true })).toBe(false);
  });

  test("rejects a missing entry", () => {
    expect(isPresentFile(undefined)).toBe(false);
  });
});
