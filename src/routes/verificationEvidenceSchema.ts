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

export const verificationEvidenceSchema = z
  .object({
    liveness: passedVerificationResultSchema,
    likeness: likenessVerificationResultSchema,
    gaze: passedVerificationResultSchema.optional(),
  })
  .strict();

export type VerificationEvidence = z.infer<typeof verificationEvidenceSchema>;
