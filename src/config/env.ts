import { z } from "zod";

const emptyToUndefined = (value: unknown): string | undefined => {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const toBoolean = (value: string): boolean => {
  const normalized = value.trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes";
};

const parsed = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    HOST: z.string().min(1).default("0.0.0.0"),
    PORT: z.coerce.number().int().min(1).max(65535).default(3001),
    SUPABASE_URL: z.string().url().optional(),
    SUPABASE_SERVICE_ROLE_KEY: z.string().min(1).optional(),
    SUPABASE_PROJECT_REF: z.string().min(1).optional(),
    ENABLE_DEV_VIEWER_AUTH: z.string().optional(),
    DEV_VIEWER_ID_HEADER: z.string().min(1).optional(),
    WALLET_ISSUER_ID: z.string().min(1).optional(),
    WALLET_ISSUER_SIGNING_SECRET: z.string().min(1).optional(),
    VERIFIED_IDENTITY_PEPPER: z.string().min(1).optional(),
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
    ENABLE_DEV_VIEWER_AUTH: emptyToUndefined(process.env.ENABLE_DEV_VIEWER_AUTH),
    DEV_VIEWER_ID_HEADER: emptyToUndefined(process.env.DEV_VIEWER_ID_HEADER),
    WALLET_ISSUER_ID: emptyToUndefined(process.env.WALLET_ISSUER_ID),
    WALLET_ISSUER_SIGNING_SECRET: emptyToUndefined(
      process.env.WALLET_ISSUER_SIGNING_SECRET,
    ),
    VERIFIED_IDENTITY_PEPPER: emptyToUndefined(process.env.VERIFIED_IDENTITY_PEPPER),
  });

const enableDevViewerAuth =
  parsed.ENABLE_DEV_VIEWER_AUTH !== undefined
    ? toBoolean(parsed.ENABLE_DEV_VIEWER_AUTH)
    : parsed.NODE_ENV !== "production";

const devViewerIdHeader = (parsed.DEV_VIEWER_ID_HEADER || "x-dev-viewer-id")
  .trim()
  .toLowerCase();

const walletIssuerId =
  parsed.WALLET_ISSUER_ID || "did:iland:backend:issuer:v0.0.86";

const walletIssuerSigningSecret =
  parsed.WALLET_ISSUER_SIGNING_SECRET || "iland-backend-wallet-issuer-dev-secret";
const verifiedIdentityPepper =
  parsed.VERIFIED_IDENTITY_PEPPER || "iland-backend-verified-identity-dev-pepper";

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
  auth: Object.freeze({
    enableDevViewerAuth,
    devViewerIdHeader,
  }),
  wallet: Object.freeze({
    issuerId: walletIssuerId,
    issuerSigningSecret: walletIssuerSigningSecret,
  }),
  verifiedIdentity: Object.freeze({
    pepper: verifiedIdentityPepper,
  }),
});

export default env;
