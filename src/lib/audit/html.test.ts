import { describe, expect, test } from "bun:test";
import { imageDimensions } from "./html";

describe("imageDimensions", () => {
  test("reads PNG dimensions", () => {
    const bytes = new Uint8Array(24);
    bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const view = new DataView(bytes.buffer);
    view.setUint32(16, 1200);
    view.setUint32(20, 630);
    expect(imageDimensions(bytes, "image/png")).toEqual({ width: 1200, height: 630, type: "PNG" });
  });

  test("reads GIF dimensions", () => {
    const bytes = new Uint8Array(10);
    bytes.set([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x20, 0x03, 0x58, 0x02]);
    expect(imageDimensions(bytes, "image/gif")).toEqual({ width: 800, height: 600, type: "GIF" });
  });

  test("returns an unknown result for an unrecognised image", () => {
    expect(imageDimensions(new Uint8Array([1, 2, 3]), "image/avif").width).toBe(0);
  });
});
