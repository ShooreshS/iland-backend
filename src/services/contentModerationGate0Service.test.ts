import { describe, expect, it } from "bun:test";
import {
  GATE0_IMAGE_LIMITS,
  GATE0_TEXT_LIMITS,
  validateModerationGate0,
} from "./contentModerationGate0Service";

describe("contentModerationGate0Service", () => {
  it("rejects empty text and no image", () => {
    expect(validateModerationGate0({ title: " ", pollOptions: [] })).toMatchObject({
      ok: false,
      reasonCode: "EMPTY_CONTENT",
    });
  });

  it("rejects text fields above configured limits", () => {
    const result = validateModerationGate0({
      title: "x".repeat(GATE0_TEXT_LIMITS.titleMaxLength + 1),
      pollOptions: ["Yes", "No"],
    });

    expect(result).toMatchObject({
      ok: false,
      reasonCode: "TEXT_TOO_LONG",
    });
  });

  it("rejects unsupported image MIME types", () => {
    const result = validateModerationGate0({
      title: "Library hours",
      pollOptions: ["Yes", "No"],
      image: {
        imageUrl: "https://example.test/image.svg",
        mimeType: "image/svg+xml",
        sizeBytes: 10_000,
      },
    });

    expect(result).toMatchObject({
      ok: false,
      reasonCode: "IMAGE_TYPE_UNSUPPORTED",
    });
  });

  it("rejects images above the configured size limit", () => {
    const result = validateModerationGate0({
      title: "Library hours",
      pollOptions: ["Yes", "No"],
      image: {
        imageUrl: "https://example.test/image.png",
        mimeType: "image/png",
        sizeBytes: GATE0_IMAGE_LIMITS.maxImageBytes + 1,
      },
    });

    expect(result).toMatchObject({
      ok: false,
      reasonCode: "IMAGE_TOO_LARGE",
    });
  });

  it("accepts supported image metadata within limits", () => {
    const result = validateModerationGate0({
      title: "Library hours",
      pollOptions: ["Yes", "No"],
      image: {
        imageUrl: "https://example.test/image.webp",
        mimeType: "image/webp",
        sizeBytes: GATE0_IMAGE_LIMITS.maxImageBytes,
        altText: "A public library at night",
      },
    });

    expect(result).toEqual({ ok: true });
  });
});
