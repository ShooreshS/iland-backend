import OpenAI from "openai";
import type { JsonValue } from "../types/json";

export const OPENAI_MODERATION_MODEL = "omni-moderation-latest" as const;
export const MODERATION_POLICY_VERSION = "gate1-v1" as const;

export type PollModerationStatus =
  | "draft"
  | "moderation_pending"
  | "published"
  | "review_required"
  | "needs_edit"
  | "blocked"
  | "moderation_error"
  | "appeal_pending"
  | "appeal_approved"
  | "appeal_rejected";

export type ModerationDecision =
  | "allow"
  | "review_required"
  | "blocked"
  | "moderation_error";

export type ModeratePostInput = {
  postId: string;
  title?: string | null;
  body?: string | null;
  pollQuestion?: string | null;
  pollOptions?: string[];
  imageUrl?: string | null;
  imageAltText?: string | null;
};

export type ModeratePostResult = {
  decision: ModerationDecision;
  moderationStatus: PollModerationStatus;
  model: string;
  flagged: boolean | null;
  categories: Record<string, boolean>;
  categoryScores: Record<string, number>;
  appliedInputTypes: Record<string, string[]>;
  raw: JsonValue | null;
  error: string | null;
  policyVersion: typeof MODERATION_POLICY_VERSION;
  moderatedAt: string;
};

type OpenAIModerationsClient = {
  moderations: {
    create: (input: any) => Promise<unknown>;
  };
};

type ContentModerationServiceDependencies = {
  client?: OpenAIModerationsClient;
  apiKey?: string | null;
  now?: () => Date;
};

const HARD_BLOCK_CATEGORIES = new Set([
  "sexual/minors",
  "hate/threatening",
  "harassment/threatening",
  "self-harm/instructions",
  "illicit/violent",
]);

const SCORE_REVIEW_THRESHOLDS: Record<string, number> = {
  hate: 0.5,
  "hate/threatening": 0.25,
  harassment: 0.6,
  "harassment/threatening": 0.25,
  violence: 0.7,
  "violence/graphic": 0.5,
  sexual: 0.7,
  "sexual/minors": 0.1,
  "self-harm": 0.5,
  "self-harm/intent": 0.3,
  "self-harm/instructions": 0.2,
  illicit: 0.6,
  "illicit/violent": 0.25,
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const readRecord = (value: unknown): Record<string, unknown> =>
  isRecord(value) ? value : {};

const readBooleanRecord = (value: unknown): Record<string, boolean> =>
  Object.fromEntries(
    Object.entries(readRecord(value)).filter(
      (entry): entry is [string, boolean] => typeof entry[1] === "boolean",
    ),
  );

const readNumberRecord = (value: unknown): Record<string, number> =>
  Object.fromEntries(
    Object.entries(readRecord(value)).filter(
      (entry): entry is [string, number] =>
        typeof entry[1] === "number" && Number.isFinite(entry[1]),
    ),
  );

const readAppliedInputTypes = (value: unknown): Record<string, string[]> =>
  Object.fromEntries(
    Object.entries(readRecord(value))
      .map(([key, inputTypes]) => [
        key,
        Array.isArray(inputTypes)
          ? inputTypes.filter(
              (inputType): inputType is string => typeof inputType === "string",
            )
          : [],
      ])
      .filter(([, inputTypes]) => inputTypes.length > 0),
  );

const readFlagged = (value: unknown): boolean | null =>
  typeof value === "boolean" ? value : null;

const compactLines = (lines: Array<string | null | undefined>): string =>
  lines
    .map((line) => (typeof line === "string" ? line.trim() : ""))
    .filter(Boolean)
    .join("\n");

export const buildModerationText = (input: ModeratePostInput): string => {
  const optionText =
    input.pollOptions && input.pollOptions.length > 0
      ? input.pollOptions
          .map((option, index) => `Option ${index + 1}: ${option.trim()}`)
          .filter((line) => !line.endsWith(":"))
          .join("\n")
      : null;

  return compactLines([
    input.title ? `Title: ${input.title}` : null,
    input.body ? `Body: ${input.body}` : null,
    input.pollQuestion ? `Poll question: ${input.pollQuestion}` : null,
    optionText ? `Poll options:\n${optionText}` : null,
    input.imageAltText ? `Image alt text: ${input.imageAltText}` : null,
  ]);
};

export const decideModerationResult = (input: {
  flagged: boolean | null;
  categories: Record<string, boolean>;
  categoryScores: Record<string, number>;
}): ModerationDecision => {
  for (const category of HARD_BLOCK_CATEGORIES) {
    if (input.categories[category]) {
      return "blocked";
    }
  }

  if (input.flagged) {
    return "review_required";
  }

  for (const [category, threshold] of Object.entries(SCORE_REVIEW_THRESHOLDS)) {
    if ((input.categoryScores[category] ?? 0) >= threshold) {
      return "review_required";
    }
  }

  return "allow";
};

const statusForDecision = (decision: ModerationDecision): PollModerationStatus => {
  switch (decision) {
    case "allow":
      return "published";
    case "review_required":
      return "review_required";
    case "blocked":
      return "blocked";
    case "moderation_error":
      return "moderation_error";
  }
};

const createErrorResult = (
  error: string,
  now: Date,
): ModeratePostResult => ({
  decision: "moderation_error",
  moderationStatus: "moderation_error",
  model: OPENAI_MODERATION_MODEL,
  flagged: null,
  categories: {},
  categoryScores: {},
  appliedInputTypes: {},
  raw: null,
  error,
  policyVersion: MODERATION_POLICY_VERSION,
  moderatedAt: now.toISOString(),
});

const getApiErrorMessage = (error: unknown): string => {
  if (error instanceof OpenAI.APIError) {
    return `openai_api_error:${error.status ?? "unknown"}`;
  }

  if (error instanceof Error) {
    return error.name || "moderation_error";
  }

  return "moderation_error";
};

export const createContentModerationService = (
  dependencies: ContentModerationServiceDependencies = {},
) => {
  const now = dependencies.now ?? (() => new Date());

  const getClient = (): OpenAIModerationsClient | null => {
    if (dependencies.client) {
      return dependencies.client;
    }

    const apiKey = dependencies.apiKey ?? process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return null;
    }

    return new OpenAI({ apiKey });
  };

  return {
    async moderatePost(input: ModeratePostInput): Promise<ModeratePostResult> {
      const moderatedAt = now();
      const client = getClient();
      if (!client) {
        return createErrorResult("openai_api_key_missing", moderatedAt);
      }

      const text = buildModerationText(input);
      if (!text && !input.imageUrl) {
        return createErrorResult("empty_moderation_input", moderatedAt);
      }

      const moderationInput: unknown[] = text
        ? [
            {
              type: "text",
              text,
            },
          ]
        : [];

      if (input.imageUrl) {
        moderationInput.push({
          type: "image_url",
          image_url: {
            url: input.imageUrl,
          },
        });
      }

      const startedAt = Date.now();
      try {
        const response = await client.moderations.create({
          model: OPENAI_MODERATION_MODEL,
          input: moderationInput,
        });
        const latencyMs = Date.now() - startedAt;
        const responseRecord = readRecord(response);
        const results = Array.isArray(responseRecord.results)
          ? responseRecord.results
          : [];
        const firstResult = readRecord(results[0]);
        const flagged = readFlagged(firstResult.flagged);
        const categories = readBooleanRecord(firstResult.categories);
        const categoryScores = readNumberRecord(firstResult.category_scores);
        const appliedInputTypes = readAppliedInputTypes(
          firstResult.category_applied_input_types,
        );

        if (flagged === null) {
          return createErrorResult("malformed_moderation_response", moderatedAt);
        }

        const decision = decideModerationResult({
          flagged,
          categories,
          categoryScores,
        });
        const model =
          typeof responseRecord.model === "string"
            ? responseRecord.model
            : OPENAI_MODERATION_MODEL;

        console.info("[moderation] completed", {
          postId: input.postId,
          model,
          decision,
          latencyMs,
        });

        return {
          decision,
          moderationStatus: statusForDecision(decision),
          model,
          flagged,
          categories,
          categoryScores,
          appliedInputTypes,
          raw: null,
          error: null,
          policyVersion: MODERATION_POLICY_VERSION,
          moderatedAt: moderatedAt.toISOString(),
        };
      } catch (error) {
        const latencyMs = Date.now() - startedAt;
        const errorMessage = getApiErrorMessage(error);
        console.warn("[moderation] failed", {
          postId: input.postId,
          model: OPENAI_MODERATION_MODEL,
          decision: "moderation_error",
          latencyMs,
          error: errorMessage,
        });

        return createErrorResult(errorMessage, moderatedAt);
      }
    },
  };
};

export const contentModerationService = createContentModerationService();

export default contentModerationService;
