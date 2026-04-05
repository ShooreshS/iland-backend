import { z } from "zod";

const emptyToUndefined = (value: unknown): string | undefined => {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const parsed = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    HOST: z.string().min(1).default("0.0.0.0"),
    PORT: z.coerce.number().int().min(1).max(65535).default(3001),
    SUPABASE_URL: z.string().url().optional(),
    SUPABASE_SERVICE_ROLE_KEY: z.string().min(1).optional(),
    SUPABASE_PROJECT_REF: z.string().min(1).optional(),
  })
  .superRefine((input, context) => {
    const hasUrl = Boolean(input.SUPABASE_URL);
    const hasServiceRoleKey = Boolean(input.SUPABASE_SERVICE_ROLE_KEY);

    if (hasUrl !== hasServiceRoleKey) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must both be set together, or both omitted.",
        path: hasUrl ? ["SUPABASE_SERVICE_ROLE_KEY"] : ["SUPABASE_URL"],
      });
    }
  })
  .parse({
    NODE_ENV: process.env.NODE_ENV,
    HOST: process.env.HOST,
    PORT: process.env.PORT,
    SUPABASE_URL: emptyToUndefined(process.env.SUPABASE_URL),
    SUPABASE_SERVICE_ROLE_KEY: emptyToUndefined(process.env.SUPABASE_SERVICE_ROLE_KEY),
    SUPABASE_PROJECT_REF: emptyToUndefined(process.env.SUPABASE_PROJECT_REF),
  });

export const env = Object.freeze({
  nodeEnv: parsed.NODE_ENV,
  host: parsed.HOST,
  port: parsed.PORT,
  supabase: Object.freeze({
    enabled: Boolean(parsed.SUPABASE_URL && parsed.SUPABASE_SERVICE_ROLE_KEY),
    url: parsed.SUPABASE_URL ?? null,
    serviceRoleKey: parsed.SUPABASE_SERVICE_ROLE_KEY ?? null,
    projectRef: parsed.SUPABASE_PROJECT_REF ?? null,
  }),
});

export default env;
