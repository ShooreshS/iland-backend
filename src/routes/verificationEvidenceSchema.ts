import { z } from "zod";

const passedVerificationResultSchema = z
  .object({
    passed: z.literal(true),
  })
  .passthrough();

const likenessVerificationResultSchema = z
  .object({
    passed: z.literal(true),
    similarity: z.number().finite(),
    threshold: z.number().finite(),
  })
  .passthrough();

const automatedVerificationEvidenceSchema = z
  .object({
    method: z.literal("device_comparison").optional(),
    liveness: passedVerificationResultSchema,
    likeness: likenessVerificationResultSchema,
    gaze: passedVerificationResultSchema.optional(),
  })
  .strict();

const humanReviewVerificationEvidenceSchema = z
  .object({
    method: z.literal("human_review"),
    liveness: passedVerificationResultSchema,
    likeness: likenessVerificationResultSchema,
    gaze: passedVerificationResultSchema.optional(),
    humanReview: z
      .object({
        requestId: z.string().uuid(),
        reviewToken: z.string().trim().min(32),
      })
      .strict(),
  })
  .strict();

export const verificationEvidenceSchema = z.union([
  humanReviewVerificationEvidenceSchema,
  automatedVerificationEvidenceSchema,
]);

export type VerificationEvidence = z.infer<typeof verificationEvidenceSchema>;
