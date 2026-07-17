import { describe, expect, it } from "bun:test";
import {
  buildModerationText,
  createContentModerationService,
  decideModerationResult,
} from "./contentModerationService";

describe("contentModerationService", () => {
  it("includes poll options and image alt text in the text moderation input", () => {
    const text = buildModerationText({
      postId: "poll-1",
      title: "Library hours",
      body: "Should the municipality extend public-library opening hours?",
      pollOptions: ["Yes", "No"],
      imageAltText: "Night bus stop outside a library",
    });

    expect(text).toContain("Title: Library hours");
    expect(text).toContain("Body: Should the municipality");
    expect(text).toContain("Option 1: Yes");
    expect(text).toContain("Option 2: No");
    expect(text).toContain("Image alt text: Night bus stop");
  });

  it("allows unflagged posts below score thresholds", () => {
    expect(
      decideModerationResult({
        flagged: false,
        categories: {
          harassment: false,
        },
        categoryScores: {
          harassment: 0.1,
        },
      }),
    ).toBe("allow");
  });

  it("requires review for flagged posts without hard-block categories", () => {
    expect(
      decideModerationResult({
        flagged: true,
        categories: {
          harassment: true,
        },
        categoryScores: {
          harassment: 0.99,
        },
      }),
    ).toBe("review_required");
  });

  it("blocks flagged hard-block categories", () => {
    expect(
      decideModerationResult({
        flagged: true,
        categories: {
          "sexual/minors": true,
        },
        categoryScores: {
          "sexual/minors": 0.99,
        },
      }),
    ).toBe("blocked");
  });

  it("requires review for score-only threshold matches", () => {
    expect(
      decideModerationResult({
        flagged: false,
        categories: {
          violence: false,
        },
        categoryScores: {
          violence: 0.7,
        },
      }),
    ).toBe("review_required");
  });

  it("normalizes OpenAI moderation responses", async () => {
    const calls: unknown[] = [];
    const service = createContentModerationService({
      now: () => new Date("2026-07-17T10:00:00.000Z"),
      client: {
        moderations: {
          create: async (payload: unknown) => {
            calls.push(payload);
            return {
              model: "omni-moderation-latest",
              results: [
                {
                  flagged: false,
                  categories: {
                    harassment: false,
                  },
                  category_scores: {
                    harassment: 0.01,
                  },
                  category_applied_input_types: {
                    harassment: ["text"],
                  },
                },
              ],
            };
          },
        },
      },
    });

    const result = await service.moderatePost({
      postId: "poll-1",
      title: "Library hours",
      pollOptions: ["Yes", "No"],
    });

    expect(calls).toHaveLength(1);
    expect(result).toMatchObject({
      decision: "allow",
      moderationStatus: "published",
      model: "omni-moderation-latest",
      flagged: false,
      categories: {
        harassment: false,
      },
      categoryScores: {
        harassment: 0.01,
      },
      appliedInputTypes: {
        harassment: ["text"],
      },
      error: null,
      policyVersion: "gate1-v1",
      moderatedAt: "2026-07-17T10:00:00.000Z",
    });
  });

  it("fails closed when the OpenAI client errors", async () => {
    const service = createContentModerationService({
      now: () => new Date("2026-07-17T10:00:00.000Z"),
      client: {
        moderations: {
          create: async () => {
            throw new Error("timeout");
          },
        },
      },
    });

    const result = await service.moderatePost({
      postId: "poll-1",
      title: "Library hours",
    });

    expect(result).toMatchObject({
      decision: "moderation_error",
      moderationStatus: "moderation_error",
      flagged: null,
      error: "Error",
    });
  });
});
