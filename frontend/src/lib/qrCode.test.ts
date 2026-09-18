import { describe, expect, it } from "vitest";
import { qrCodeImageSrc } from "./qrCode";

describe("qrCodeImageSrc", () => {
  it("turns the server's bare base64 into a PNG data URL", () => {
    expect(qrCodeImageSrc("iVBORw0KGgo=")).toBe(
      "data:image/png;base64,iVBORw0KGgo=",
    );
  });

  it("passes a value that is already a data URL through unchanged", () => {
    const url = "data:image/png;base64,iVBORw0KGgo=";
    expect(qrCodeImageSrc(url)).toBe(url);
  });
});
