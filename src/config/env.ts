import { z } from "zod";

import {
  BALLOT_CUSTODY_MODES,
  OPERATOR_TRUSTED_PRIVATE_BETA_CUSTODY_MODE,
  THRESHOLD_TRUSTEE_CUSTODY_MODE,
} from "./ballotCustodyDefaults";
import {
  CIVICOS_AUDIT_PROGRAM_ID,
  DEFAULT_SOLANA_AUDIT_FEE_MODE,
  SHOLAN_TOKEN_DEFAULTS,
  SOLANA_AUDIT_CLUSTERS,
  SOLANA_AUDIT_FEE_MODES,
  SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
} from "./solanaAuditDefaults";
import {
  DEFAULT_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION,
  DEFAULT_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH,
  DEFAULT_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH,
  DEFAULT_GROTH16_TALLY_CIRCUIT_ID,
  DEFAULT_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  DEFAULT_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH,
  DEFAULT_GROTH16_TALLY_VERIFIER_KEY_HASH,
  DEFAULT_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH,
  DEFAULT_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH,
  DEFAULT_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH,
  DEFAULT_GROTH16_VOTE_CIRCUIT_ID,
  DEFAULT_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION,
  DEFAULT_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH,
  DEFAULT_GROTH16_VOTE_VERIFIER_KEY_HASH,
} from "./zkpGroth16ArtifactDefaults";

const stripWrappingQuotes = (value: string): string => {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }

  return trimmed;
};

const emptyToUndefined = (value: unknown): string | undefined => {
  if (typeof value !== "string") {
    return undefined;
  }

  const normalized = stripWrappingQuotes(value).trim();
  return normalized.length > 0 ? normalized : undefined;
};

const toBoolean = (value: string): boolean => {
  const normalized = stripWrappingQuotes(value).trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes";
};

const solanaPublicKeySchema = z
  .string()
  .regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/u, "Invalid Solana public key.");

const hex64Schema = z
  .string()
  .regex(/^[0-9a-f]{64}$/iu, "Expected a 32-byte hex hash.");

const SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY_MODES = [
  "backend_fee_payer_devnet",
  "external_kms_hsm_or_multisig_signing_service",
] as const;

const SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY_MODES = [
  "developer_wallet",
  "multisig_timelock",
  "immutable",
  "external_governance",
] as const;

const ZKP_RELEASE_CHANNELS = [
  "private_beta",
  "public_devnet_v0_1",
] as const;

const ZKP_ARTIFACT_RELEASE_STAGES = [
  "internal_rc",
  "ceremony_pending",
  "production_final",
] as const;

const ZKP_TALLY_PROVER_MODES = ["inline", "worker", "disabled"] as const;

const normalizeAndroidCertDigest = (value: string): string => {
  const trimmed = value.trim();
  const hexCandidate = trimmed.replace(/:/g, "");
  if (/^[a-f0-9]+$/i.test(hexCandidate) && hexCandidate.length === 64) {
    return hexCandidate.toLowerCase();
  }

  const base64Candidate = trimmed.replace(/=+$/u, "");
  if (/^[a-z0-9_-]+$/i.test(base64Candidate) && base64Candidate.length === 43) {
    try {
      const padded = base64Candidate
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(Math.ceil(base64Candidate.length / 4) * 4, "=");
      const decoded = Buffer.from(padded, "base64");
      if (decoded.length === 32) {
        return decoded.toString("hex");
      }
    } catch {
      // Fall through to lowercase normalization for unusual future formats.
    }
  }

  return trimmed.toLowerCase();
};

const parsed = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    ILAND_ENV_VALIDATION_SCOPE: z
      .enum(["server", "supabase-admin-script"])
      .default("server"),
    HOST: z.string().min(1).default("0.0.0.0"),
    PORT: z.coerce.number().int().min(1).max(65535).default(3001),
    SUPABASE_URL: z.string().url().optional(),
    SUPABASE_SERVICE_ROLE_KEY: z.string().min(1).optional(),
    SUPABASE_PROJECT_REF: z.string().min(1).optional(),
    AUTH_ISSUER: z.string().url().optional(),
    AUTH_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).optional(),
    AUTH_REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).optional(),
    AUTH_MAX_ACTIVE_SESSIONS_PER_USER: z.coerce.number().int().min(1).optional(),
    AUTH_REQUIRE_ATTESTED_SESSIONS_FOR_PROTECTED_ROUTES: z.string().optional(),
    AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS: z.string().optional(),
    AUTH_IOS_TEAM_ID: z.string().min(1).optional(),
    AUTH_IOS_BUNDLE_ID: z.string().min(1).optional(),
    AUTH_ANDROID_PACKAGE_NAME: z.string().min(1).optional(),
    AUTH_IOS_APP_ATTEST_ENVIRONMENT: z
      .enum(["development", "production"])
      .optional(),
    AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS: z.string().optional(),
    AUTH_ANDROID_GOOGLE_API_KEY: z.string().min(1).optional(),
    AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON: z.string().min(1).optional(),
    AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL: z.string().min(1).optional(),
    AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: z.string().min(1).optional(),
    AUTH_ANDROID_REQUIRE_STRONG_INTEGRITY: z.string().optional(),
    WALLET_ISSUER_ID: z.string().min(1).optional(),
    WALLET_ISSUER_SIGNING_SECRET: z.string().min(1).optional(),
    VERIFIED_IDENTITY_PEPPER: z.string().min(1).optional(),
    OPENAI_API_KEY: z.string().min(1).optional(),
    POLL_MAP_REFRESH_WORKER_ENABLED: z.string().optional(),
    POLL_MAP_REFRESH_INTERVAL_MS: z.coerce.number().int().min(250).optional(),
    POLL_MAP_REFRESH_PENDING_THRESHOLD: z.coerce.number().int().min(1).optional(),
    POLL_MAP_REFRESH_MAX_DELAY_MS: z.coerce.number().int().min(0).optional(),
    POLL_MAP_REFRESH_MAX_POLLS_PER_CYCLE: z.coerce.number().int().min(1).optional(),
    POLL_MAP_REFRESH_FAILURE_COOLDOWN_MS: z.coerce.number().int().min(0).optional(),
    MAP_ENABLE_ALL_POLLS_DEBUG: z.string().optional(),
    SOLANA_AUDIT_CLUSTER: z.enum(SOLANA_AUDIT_CLUSTERS).optional(),
    SOLANA_AUDIT_RPC_URL: z.string().url().optional(),
    SOLANA_AUDIT_TOKEN_MINT: solanaPublicKeySchema.optional(),
    SOLANA_AUDIT_TOKEN_PROGRAM: solanaPublicKeySchema.optional(),
    SOLANA_AUDIT_PROGRAM_ID: solanaPublicKeySchema.optional(),
    SOLANA_AUDIT_REGISTRY_AUTHORITY: solanaPublicKeySchema.optional(),
    SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY: solanaPublicKeySchema.optional(),
    SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY: z
      .enum(SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY_MODES)
      .optional(),
    SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY: solanaPublicKeySchema.optional(),
    SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY: z
      .enum(SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY_MODES)
      .optional(),
    SOLANA_AUDIT_TREASURY: solanaPublicKeySchema.optional(),
    SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY: solanaPublicKeySchema.optional(),
    SOLANA_AUDIT_FEE_PAYER_SECRET_KEY: z.string().min(1).optional(),
    SOLANA_AUDIT_DEFAULT_FEE_MODE: z.enum(SOLANA_AUDIT_FEE_MODES).optional(),
    SOLANA_AUDIT_SPONSORSHIP_ENABLED: z.string().optional(),
    SOLANA_AUDIT_USER_PAID_FEES_ENABLED: z.string().optional(),
    SOLANA_AUDIT_TRANSACTIONS_ENABLED: z.string().optional(),
    SOLANA_AUDIT_MAINNET_CONFIRMED: z.string().optional(),
    ZKP_GROTH16_VOTE_VERIFIER_ENABLED: z.string().optional(),
    ZKP_GROTH16_VOTE_CIRCUIT_ID: z.string().min(1).optional(),
    ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH: hex64Schema.optional(),
    ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION: z.string().min(1).optional(),
    ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH: hex64Schema.optional(),
    ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION: z.string().min(1).optional(),
    ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH: hex64Schema.optional(),
    ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH: z.string().min(1).optional(),
    ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH: hex64Schema.optional(),
    ZKP_GROTH16_TALLY_VERIFIER_ENABLED: z.string().optional(),
    ZKP_GROTH16_TALLY_CIRCUIT_ID: z.string().min(1).optional(),
    ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH: hex64Schema.optional(),
    ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION: z.string().min(1).optional(),
    ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH: hex64Schema.optional(),
    ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH: z.string().min(1).optional(),
    ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH: hex64Schema.optional(),
    ZKP_BALLOT_CUSTODY_MODE: z.enum(BALLOT_CUSTODY_MODES).optional(),
    ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED: z.string().optional(),
    ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED: z.string().optional(),
    ZKP_RELEASE_CHANNEL: z.enum(ZKP_RELEASE_CHANNELS).optional(),
    ZKP_ARTIFACT_RELEASE_STAGE: z
      .enum(ZKP_ARTIFACT_RELEASE_STAGES)
      .optional(),
    ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED: z.string().optional(),
    ZKP_TALLY_PROVER_MODE: z.enum(ZKP_TALLY_PROVER_MODES).optional(),
    ZKP_TALLY_WORKER_ENABLED: z.string().optional(),
    ZKP_TALLY_WORKER_ID: z.string().min(1).optional(),
    ZKP_TALLY_WORKER_CONCURRENCY: z.coerce.number().int().min(1).optional(),
    ZKP_TALLY_WORKER_POLL_INTERVAL_MS: z.coerce.number().int().min(250).optional(),
    ZKP_TALLY_WORKER_LOCK_TIMEOUT_MS: z.coerce.number().int().min(1_000).optional(),
    ZKP_TALLY_WORKER_MAX_ATTEMPTS: z.coerce.number().int().min(1).optional(),
    ZKP_TALLY_WORKER_RETRY_DELAY_MS: z.coerce.number().int().min(0).optional(),
    ZKP_TALLY_WORKER_HEARTBEAT_STALE_MS: z.coerce
      .number()
      .int()
      .min(1_000)
      .optional(),
    ZKP_TALLY_WORKER_REQUIRED_FOR_PRODUCTION: z.string().optional(),
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

    const transitionalBypassEnabled =
      input.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS !== undefined
        ? toBoolean(input.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS)
        : input.NODE_ENV !== "production";

    const skipServerOnlyAuthValidation =
      input.ILAND_ENV_VALIDATION_SCOPE === "supabase-admin-script";

    // Intention:
    // Production server startup must fail closed when app-attestation auth is
    // misconfigured. Supabase admin scripts such as OIDC key seeding do not
    // serve requests and only need DB credentials, so they opt out explicitly.
    if (
      !skipServerOnlyAuthValidation &&
      input.NODE_ENV === "production" &&
      transitionalBypassEnabled
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS must be false in production.",
        path: ["AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS"],
      });
    }

    if (
      !skipServerOnlyAuthValidation &&
      input.NODE_ENV === "production" &&
      !input.OPENAI_API_KEY
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "OPENAI_API_KEY is required in production because poll publishing uses backend moderation.",
        path: ["OPENAI_API_KEY"],
      });
    }

    if (
      !skipServerOnlyAuthValidation &&
      !transitionalBypassEnabled &&
      !input.AUTH_IOS_TEAM_ID
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "AUTH_IOS_TEAM_ID is required when real App Attest verification is enabled.",
        path: ["AUTH_IOS_TEAM_ID"],
      });
    }

    const hasAndroidGoogleServiceAccountJson = Boolean(
      input.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON,
    );
    const hasAndroidGoogleServiceAccountParts = Boolean(
      input.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL &&
        input.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY,
    );
    if (
      !skipServerOnlyAuthValidation &&
      !transitionalBypassEnabled &&
      !hasAndroidGoogleServiceAccountJson &&
      !hasAndroidGoogleServiceAccountParts
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON or AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL/AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY is required when real Play Integrity verification is enabled.",
        path: ["AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON"],
      });
    }

    const allowedAndroidSigningDigests = (input.AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    if (
      !skipServerOnlyAuthValidation &&
      !transitionalBypassEnabled &&
      allowedAndroidSigningDigests.length === 0
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS is required when real Play Integrity verification is enabled.",
        path: ["AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS"],
      });
    }

    const hasSolanaAuditTokenMint = Boolean(input.SOLANA_AUDIT_TOKEN_MINT);
    const hasSolanaAuditTokenProgram = Boolean(input.SOLANA_AUDIT_TOKEN_PROGRAM);
    if (hasSolanaAuditTokenMint !== hasSolanaAuditTokenProgram) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "SOLANA_AUDIT_TOKEN_MINT and SOLANA_AUDIT_TOKEN_PROGRAM must both be set together, or both omitted.",
        path: hasSolanaAuditTokenMint
          ? ["SOLANA_AUDIT_TOKEN_PROGRAM"]
          : ["SOLANA_AUDIT_TOKEN_MINT"],
      });
    }

    const solanaAuditTransactionsEnabled =
      input.SOLANA_AUDIT_TRANSACTIONS_ENABLED !== undefined
        ? toBoolean(input.SOLANA_AUDIT_TRANSACTIONS_ENABLED)
        : false;
    const solanaAuditCluster =
      input.SOLANA_AUDIT_CLUSTER || SHOLAN_TOKEN_DEFAULTS.cluster;
    const solanaAuditMainnetConfirmed =
      input.SOLANA_AUDIT_MAINNET_CONFIRMED !== undefined
        ? toBoolean(input.SOLANA_AUDIT_MAINNET_CONFIRMED)
        : false;
    const solanaAuditRootPublisherPublicKey =
      input.SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY ??
      input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY;
    const zkpReleaseChannel = input.ZKP_RELEASE_CHANNEL ?? "private_beta";
    const zkpArtifactReleaseStage =
      input.ZKP_ARTIFACT_RELEASE_STAGE ?? "internal_rc";
    const zkpPublicDevnetV01Confirmed =
      input.ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED !== undefined
        ? toBoolean(input.ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED)
        : false;

    if (
      input.SOLANA_AUDIT_REGISTRY_AUTHORITY &&
      solanaAuditRootPublisherPublicKey &&
      input.SOLANA_AUDIT_REGISTRY_AUTHORITY === solanaAuditRootPublisherPublicKey
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "SOLANA_AUDIT_REGISTRY_AUTHORITY and SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY must be different.",
        path: ["SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY"],
      });
    }

    if (solanaAuditTransactionsEnabled) {
      if (!input.SOLANA_AUDIT_REGISTRY_AUTHORITY) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "SOLANA_AUDIT_REGISTRY_AUTHORITY is required when Solana audit transactions are enabled.",
          path: ["SOLANA_AUDIT_REGISTRY_AUTHORITY"],
        });
      }

      if (!input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY is required when Solana audit transactions are enabled.",
          path: ["SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY"],
        });
      }

      if (!input.SOLANA_AUDIT_FEE_PAYER_SECRET_KEY) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "SOLANA_AUDIT_FEE_PAYER_SECRET_KEY is required when Solana audit transactions are enabled.",
          path: ["SOLANA_AUDIT_FEE_PAYER_SECRET_KEY"],
        });
      }

      const rootPublisherCustody =
        input.SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY ??
        (solanaAuditRootPublisherPublicKey &&
        input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY &&
        solanaAuditRootPublisherPublicKey !== input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY
          ? "external_kms_hsm_or_multisig_signing_service"
          : "backend_fee_payer_devnet");
      const programUpgradeCustody =
        input.SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY ??
        "developer_wallet";

      if (solanaAuditCluster === "mainnet-beta" && !solanaAuditMainnetConfirmed) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "SOLANA_AUDIT_MAINNET_CONFIRMED must be true before enabling Solana audit transactions on mainnet-beta.",
          path: ["SOLANA_AUDIT_MAINNET_CONFIRMED"],
        });
      }

      if (solanaAuditCluster === "mainnet-beta") {
        if (!input.SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              "SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY must be explicit before enabling mainnet Solana audit transactions.",
            path: ["SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY"],
          });
        }

        if (
          solanaAuditRootPublisherPublicKey &&
          input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY &&
          solanaAuditRootPublisherPublicKey === input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY
        ) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              "SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY and SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY must be different before mainnet.",
            path: ["SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY"],
          });
        }

        if (
          input.SOLANA_AUDIT_REGISTRY_AUTHORITY &&
          input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY &&
          input.SOLANA_AUDIT_REGISTRY_AUTHORITY === input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY
        ) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              "SOLANA_AUDIT_REGISTRY_AUTHORITY and SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY must be different before mainnet.",
            path: ["SOLANA_AUDIT_REGISTRY_AUTHORITY"],
          });
        }

        if (
          rootPublisherCustody !==
          "external_kms_hsm_or_multisig_signing_service"
        ) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              "SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY must be external_kms_hsm_or_multisig_signing_service before mainnet.",
            path: ["SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY"],
          });
        }

        if (programUpgradeCustody === "developer_wallet") {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              "SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY must be multisig_timelock, immutable, or external_governance before mainnet.",
            path: ["SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY"],
          });
        }

        const upgradeAuthority = input.SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY;
        if (
          upgradeAuthority &&
          [
            input.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY,
            input.SOLANA_AUDIT_REGISTRY_AUTHORITY,
            solanaAuditRootPublisherPublicKey,
          ].includes(upgradeAuthority)
        ) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              "SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY must be distinct from fee payer, registry authority, and root publisher before mainnet.",
            path: ["SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY"],
          });
        }
      }
    }

    if (zkpReleaseChannel === "public_devnet_v0_1") {
      if (solanaAuditCluster !== "devnet") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_RELEASE_CHANNEL=public_devnet_v0_1 requires SOLANA_AUDIT_CLUSTER=devnet.",
          path: ["ZKP_RELEASE_CHANNEL"],
        });
      }

      if (solanaAuditMainnetConfirmed) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP public devnet v0.1 release must keep SOLANA_AUDIT_MAINNET_CONFIRMED=false.",
          path: ["SOLANA_AUDIT_MAINNET_CONFIRMED"],
        });
      }

      if (!zkpPublicDevnetV01Confirmed) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED=true is required to run the public v0.1 campaign on devnet.",
          path: ["ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED"],
        });
      }
    }

    const groth16VoteVerifierEnabled =
      input.ZKP_GROTH16_VOTE_VERIFIER_ENABLED !== undefined
        ? toBoolean(input.ZKP_GROTH16_VOTE_VERIFIER_ENABLED)
        : false;

    const ballotCustodyMode =
      input.ZKP_BALLOT_CUSTODY_MODE ??
      OPERATOR_TRUSTED_PRIVATE_BETA_CUSTODY_MODE;
    const publicSecretBallotClaimsEnabled =
      input.ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED !== undefined
        ? toBoolean(input.ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED)
        : false;
    const liveProvisionalResultsEnabled =
      input.ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED !== undefined
        ? toBoolean(input.ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED)
        : ballotCustodyMode !== THRESHOLD_TRUSTEE_CUSTODY_MODE;

    if (
      publicSecretBallotClaimsEnabled &&
      ballotCustodyMode !== THRESHOLD_TRUSTEE_CUSTODY_MODE
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED requires ZKP_BALLOT_CUSTODY_MODE=threshold_trustee_v1.",
        path: ["ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED"],
      });
    }

    if (
      ballotCustodyMode === THRESHOLD_TRUSTEE_CUSTODY_MODE &&
      liveProvisionalResultsEnabled
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED must be false for threshold trustee custody.",
        path: ["ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED"],
      });
    }

    if (groth16VoteVerifierEnabled) {
      const votePublicInputSchemaVersion =
        input.ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION ??
        input.ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION;
      const voteTrustedSetupTranscriptHash =
        input.ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH ??
        input.ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH;

      if (!input.ZKP_GROTH16_VOTE_CIRCUIT_ID) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_VOTE_CIRCUIT_ID is required when Groth16 vote verification is enabled.",
          path: ["ZKP_GROTH16_VOTE_CIRCUIT_ID"],
        });
      }

      if (!input.ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH is required when Groth16 vote verification is enabled.",
          path: ["ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH"],
        });
      }

      if (!votePublicInputSchemaVersion) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION is required when Groth16 vote verification is enabled.",
          path: ["ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION"],
        });
      }

      if (!voteTrustedSetupTranscriptHash) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH is required when Groth16 vote verification is enabled.",
          path: ["ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH"],
        });
      }

      if (!input.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH is required when Groth16 vote verification is enabled.",
          path: ["ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH"],
        });
      }

      if (!input.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH is required when Groth16 vote verification is enabled.",
          path: ["ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH"],
        });
      }
    }

    const groth16TallyVerifierEnabled =
      input.ZKP_GROTH16_TALLY_VERIFIER_ENABLED !== undefined
        ? toBoolean(input.ZKP_GROTH16_TALLY_VERIFIER_ENABLED)
        : false;

    if (groth16TallyVerifierEnabled) {
      if (!input.ZKP_GROTH16_TALLY_CIRCUIT_ID) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_TALLY_CIRCUIT_ID is required when Groth16 tally verification is enabled.",
          path: ["ZKP_GROTH16_TALLY_CIRCUIT_ID"],
        });
      }

      if (!input.ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH is required when Groth16 tally verification is enabled.",
          path: ["ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH"],
        });
      }

      if (!input.ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION is required when Groth16 tally verification is enabled.",
          path: ["ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION"],
        });
      }

      if (!input.ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH is required when Groth16 tally verification is enabled.",
          path: ["ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH"],
        });
      }

      if (!input.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH is required when Groth16 tally verification is enabled.",
          path: ["ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH"],
        });
      }

      if (!input.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH is required when Groth16 tally verification is enabled.",
          path: ["ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH"],
        });
      }
    }
  })
  .parse({
    NODE_ENV: process.env.NODE_ENV,
    ILAND_ENV_VALIDATION_SCOPE: process.env.ILAND_ENV_VALIDATION_SCOPE,
    HOST: process.env.HOST,
    PORT: process.env.PORT,
    SUPABASE_URL: emptyToUndefined(process.env.SUPABASE_URL),
    SUPABASE_SERVICE_ROLE_KEY: emptyToUndefined(process.env.SUPABASE_SERVICE_ROLE_KEY),
    SUPABASE_PROJECT_REF: emptyToUndefined(process.env.SUPABASE_PROJECT_REF),
    AUTH_ISSUER: emptyToUndefined(process.env.AUTH_ISSUER),
    AUTH_ACCESS_TOKEN_TTL_SECONDS: emptyToUndefined(
      process.env.AUTH_ACCESS_TOKEN_TTL_SECONDS,
    ),
    AUTH_REFRESH_TOKEN_TTL_DAYS: emptyToUndefined(
      process.env.AUTH_REFRESH_TOKEN_TTL_DAYS,
    ),
    AUTH_MAX_ACTIVE_SESSIONS_PER_USER: emptyToUndefined(
      process.env.AUTH_MAX_ACTIVE_SESSIONS_PER_USER,
    ),
    AUTH_REQUIRE_ATTESTED_SESSIONS_FOR_PROTECTED_ROUTES: emptyToUndefined(
      process.env.AUTH_REQUIRE_ATTESTED_SESSIONS_FOR_PROTECTED_ROUTES,
    ),
    AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS: emptyToUndefined(
      process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS,
    ),
    AUTH_IOS_TEAM_ID: emptyToUndefined(process.env.AUTH_IOS_TEAM_ID),
    AUTH_IOS_BUNDLE_ID: emptyToUndefined(process.env.AUTH_IOS_BUNDLE_ID),
    AUTH_ANDROID_PACKAGE_NAME: emptyToUndefined(
      process.env.AUTH_ANDROID_PACKAGE_NAME,
    ),
    AUTH_IOS_APP_ATTEST_ENVIRONMENT: emptyToUndefined(
      process.env.AUTH_IOS_APP_ATTEST_ENVIRONMENT,
    ) as "development" | "production" | undefined,
    AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS: emptyToUndefined(
      process.env.AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS,
    ),
    AUTH_ANDROID_GOOGLE_API_KEY: emptyToUndefined(
      process.env.AUTH_ANDROID_GOOGLE_API_KEY,
    ),
    AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON: emptyToUndefined(
      process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON,
    ),
    AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL: emptyToUndefined(
      process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL,
    ),
    AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: emptyToUndefined(
      process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY,
    ),
    AUTH_ANDROID_REQUIRE_STRONG_INTEGRITY: emptyToUndefined(
      process.env.AUTH_ANDROID_REQUIRE_STRONG_INTEGRITY,
    ),
    WALLET_ISSUER_ID: emptyToUndefined(process.env.WALLET_ISSUER_ID),
    WALLET_ISSUER_SIGNING_SECRET: emptyToUndefined(
      process.env.WALLET_ISSUER_SIGNING_SECRET,
    ),
    VERIFIED_IDENTITY_PEPPER: emptyToUndefined(process.env.VERIFIED_IDENTITY_PEPPER),
    OPENAI_API_KEY: emptyToUndefined(process.env.OPENAI_API_KEY),
    POLL_MAP_REFRESH_WORKER_ENABLED: emptyToUndefined(
      process.env.POLL_MAP_REFRESH_WORKER_ENABLED,
    ),
    POLL_MAP_REFRESH_INTERVAL_MS: emptyToUndefined(
      process.env.POLL_MAP_REFRESH_INTERVAL_MS,
    ),
    POLL_MAP_REFRESH_PENDING_THRESHOLD: emptyToUndefined(
      process.env.POLL_MAP_REFRESH_PENDING_THRESHOLD,
    ),
    POLL_MAP_REFRESH_MAX_DELAY_MS: emptyToUndefined(
      process.env.POLL_MAP_REFRESH_MAX_DELAY_MS,
    ),
    POLL_MAP_REFRESH_MAX_POLLS_PER_CYCLE: emptyToUndefined(
      process.env.POLL_MAP_REFRESH_MAX_POLLS_PER_CYCLE,
    ),
    POLL_MAP_REFRESH_FAILURE_COOLDOWN_MS: emptyToUndefined(
      process.env.POLL_MAP_REFRESH_FAILURE_COOLDOWN_MS,
    ),
    MAP_ENABLE_ALL_POLLS_DEBUG: emptyToUndefined(
      process.env.MAP_ENABLE_ALL_POLLS_DEBUG,
    ),
    SOLANA_AUDIT_CLUSTER: emptyToUndefined(process.env.SOLANA_AUDIT_CLUSTER) as
      | (typeof SOLANA_AUDIT_CLUSTERS)[number]
      | undefined,
    SOLANA_AUDIT_RPC_URL: emptyToUndefined(process.env.SOLANA_AUDIT_RPC_URL),
    SOLANA_AUDIT_TOKEN_MINT: emptyToUndefined(
      process.env.SOLANA_AUDIT_TOKEN_MINT,
    ),
    SOLANA_AUDIT_TOKEN_PROGRAM: emptyToUndefined(
      process.env.SOLANA_AUDIT_TOKEN_PROGRAM,
    ),
    SOLANA_AUDIT_PROGRAM_ID: emptyToUndefined(
      process.env.SOLANA_AUDIT_PROGRAM_ID,
    ),
    SOLANA_AUDIT_REGISTRY_AUTHORITY: emptyToUndefined(
      process.env.SOLANA_AUDIT_REGISTRY_AUTHORITY,
    ),
    SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY: emptyToUndefined(
      process.env.SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY,
    ),
    SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY: emptyToUndefined(
      process.env.SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY,
    ) as (typeof SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY_MODES)[number] | undefined,
    SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY: emptyToUndefined(
      process.env.SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY,
    ),
    SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY: emptyToUndefined(
      process.env.SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY,
    ) as
      | (typeof SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY_MODES)[number]
      | undefined,
    SOLANA_AUDIT_TREASURY: emptyToUndefined(process.env.SOLANA_AUDIT_TREASURY),
    SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY: emptyToUndefined(
      process.env.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY,
    ),
    SOLANA_AUDIT_FEE_PAYER_SECRET_KEY: emptyToUndefined(
      process.env.SOLANA_AUDIT_FEE_PAYER_SECRET_KEY,
    ),
    SOLANA_AUDIT_DEFAULT_FEE_MODE: emptyToUndefined(
      process.env.SOLANA_AUDIT_DEFAULT_FEE_MODE,
    ) as (typeof SOLANA_AUDIT_FEE_MODES)[number] | undefined,
    SOLANA_AUDIT_SPONSORSHIP_ENABLED: emptyToUndefined(
      process.env.SOLANA_AUDIT_SPONSORSHIP_ENABLED,
    ),
    SOLANA_AUDIT_USER_PAID_FEES_ENABLED: emptyToUndefined(
      process.env.SOLANA_AUDIT_USER_PAID_FEES_ENABLED,
    ),
    SOLANA_AUDIT_TRANSACTIONS_ENABLED: emptyToUndefined(
      process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED,
    ),
    SOLANA_AUDIT_MAINNET_CONFIRMED: emptyToUndefined(
      process.env.SOLANA_AUDIT_MAINNET_CONFIRMED,
    ),
    ZKP_GROTH16_VOTE_VERIFIER_ENABLED: emptyToUndefined(
      process.env.ZKP_GROTH16_VOTE_VERIFIER_ENABLED,
    ),
    ZKP_GROTH16_VOTE_CIRCUIT_ID: emptyToUndefined(
      process.env.ZKP_GROTH16_VOTE_CIRCUIT_ID,
    ) ?? DEFAULT_GROTH16_VOTE_CIRCUIT_ID,
    ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH: emptyToUndefined(
      process.env.ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH,
    ) ?? DEFAULT_GROTH16_VOTE_VERIFIER_KEY_HASH,
    ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION: emptyToUndefined(
      process.env.ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION,
    ) ?? emptyToUndefined(process.env.ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION)
      ?? DEFAULT_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION,
    ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH: emptyToUndefined(
      process.env.ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH,
    ) ?? emptyToUndefined(process.env.ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH)
      ?? DEFAULT_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH,
    ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION: emptyToUndefined(
      process.env.ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION,
    ) ?? DEFAULT_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION,
    ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH: emptyToUndefined(
      process.env.ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH,
    ) ?? DEFAULT_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH,
    ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH: emptyToUndefined(
      process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH,
    ) ?? DEFAULT_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH,
    ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH: emptyToUndefined(
      process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH,
    ) ?? DEFAULT_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH,
    ZKP_GROTH16_TALLY_VERIFIER_ENABLED: emptyToUndefined(
      process.env.ZKP_GROTH16_TALLY_VERIFIER_ENABLED,
    ),
    ZKP_GROTH16_TALLY_CIRCUIT_ID: emptyToUndefined(
      process.env.ZKP_GROTH16_TALLY_CIRCUIT_ID,
    ) ?? DEFAULT_GROTH16_TALLY_CIRCUIT_ID,
    ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH: emptyToUndefined(
      process.env.ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH,
    ) ?? DEFAULT_GROTH16_TALLY_VERIFIER_KEY_HASH,
    ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION: emptyToUndefined(
      process.env.ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    ) ?? DEFAULT_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH: emptyToUndefined(
      process.env.ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH,
    ) ?? DEFAULT_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH,
    ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH: emptyToUndefined(
      process.env.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH,
    ) ?? DEFAULT_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH,
    ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH: emptyToUndefined(
      process.env.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH,
    ) ?? DEFAULT_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH,
    ZKP_BALLOT_CUSTODY_MODE: emptyToUndefined(
      process.env.ZKP_BALLOT_CUSTODY_MODE,
    ) as (typeof BALLOT_CUSTODY_MODES)[number] | undefined,
    ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED: emptyToUndefined(
      process.env.ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED,
    ),
    ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED: emptyToUndefined(
      process.env.ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED,
    ),
    ZKP_RELEASE_CHANNEL: emptyToUndefined(process.env.ZKP_RELEASE_CHANNEL) as
      | (typeof ZKP_RELEASE_CHANNELS)[number]
      | undefined,
    ZKP_ARTIFACT_RELEASE_STAGE: emptyToUndefined(
      process.env.ZKP_ARTIFACT_RELEASE_STAGE,
    ) as (typeof ZKP_ARTIFACT_RELEASE_STAGES)[number] | undefined,
    ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED: emptyToUndefined(
      process.env.ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED,
    ),
    ZKP_TALLY_PROVER_MODE: emptyToUndefined(
      process.env.ZKP_TALLY_PROVER_MODE,
    ) as (typeof ZKP_TALLY_PROVER_MODES)[number] | undefined,
    ZKP_TALLY_WORKER_ENABLED: emptyToUndefined(
      process.env.ZKP_TALLY_WORKER_ENABLED,
    ),
    ZKP_TALLY_WORKER_ID: emptyToUndefined(process.env.ZKP_TALLY_WORKER_ID),
    ZKP_TALLY_WORKER_CONCURRENCY: emptyToUndefined(
      process.env.ZKP_TALLY_WORKER_CONCURRENCY,
    ),
    ZKP_TALLY_WORKER_POLL_INTERVAL_MS: emptyToUndefined(
      process.env.ZKP_TALLY_WORKER_POLL_INTERVAL_MS,
    ),
    ZKP_TALLY_WORKER_LOCK_TIMEOUT_MS: emptyToUndefined(
      process.env.ZKP_TALLY_WORKER_LOCK_TIMEOUT_MS,
    ),
    ZKP_TALLY_WORKER_MAX_ATTEMPTS: emptyToUndefined(
      process.env.ZKP_TALLY_WORKER_MAX_ATTEMPTS,
    ),
    ZKP_TALLY_WORKER_RETRY_DELAY_MS: emptyToUndefined(
      process.env.ZKP_TALLY_WORKER_RETRY_DELAY_MS,
    ),
    ZKP_TALLY_WORKER_HEARTBEAT_STALE_MS: emptyToUndefined(
      process.env.ZKP_TALLY_WORKER_HEARTBEAT_STALE_MS,
    ),
    ZKP_TALLY_WORKER_REQUIRED_FOR_PRODUCTION: emptyToUndefined(
      process.env.ZKP_TALLY_WORKER_REQUIRED_FOR_PRODUCTION,
    ),
  });

const authIssuer =
  parsed.AUTH_ISSUER || "https://iland-backend-production.up.railway.app/idp";
const authAccessTokenTtlSeconds = parsed.AUTH_ACCESS_TOKEN_TTL_SECONDS || 15 * 60;
const authRefreshTokenTtlDays = parsed.AUTH_REFRESH_TOKEN_TTL_DAYS || 30;
const authMaxActiveSessionsPerUser =
  parsed.AUTH_MAX_ACTIVE_SESSIONS_PER_USER || 3;
const authRequireAttestedSessionsForProtectedRoutes =
  parsed.AUTH_REQUIRE_ATTESTED_SESSIONS_FOR_PROTECTED_ROUTES !== undefined
    ? toBoolean(parsed.AUTH_REQUIRE_ATTESTED_SESSIONS_FOR_PROTECTED_ROUTES)
    : true;
const authEnableTransitionalCryptoBypass =
  parsed.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS !== undefined
    ? toBoolean(parsed.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS)
    : parsed.NODE_ENV !== "production";
const authIosTeamId = parsed.AUTH_IOS_TEAM_ID || null;
const authIosBundleId = parsed.AUTH_IOS_BUNDLE_ID || "com.shooresh.iland";
const authAndroidPackageName =
  parsed.AUTH_ANDROID_PACKAGE_NAME || "com.shooresh.iland";
const authIosAppAttestEnvironment =
  parsed.AUTH_IOS_APP_ATTEST_ENVIRONMENT ||
  (parsed.NODE_ENV === "production" ? "production" : "development");
const authAndroidAllowedSigningCertDigests = (
  parsed.AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS || ""
)
  .split(",")
  .map((value) => normalizeAndroidCertDigest(value))
  .filter(Boolean);
const authAndroidGoogleApiKey = parsed.AUTH_ANDROID_GOOGLE_API_KEY || null;
const authAndroidGoogleServiceAccountJson =
  parsed.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON || null;
const authAndroidGoogleServiceAccountClientEmail =
  parsed.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL || null;
const authAndroidGoogleServiceAccountPrivateKey =
  parsed.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY?.replace(/\\n/g, "\n") ||
  null;
const authAndroidRequireStrongIntegrity =
  parsed.AUTH_ANDROID_REQUIRE_STRONG_INTEGRITY !== undefined
    ? toBoolean(parsed.AUTH_ANDROID_REQUIRE_STRONG_INTEGRITY)
    : false;

const walletIssuerId =
  parsed.WALLET_ISSUER_ID || "did:iland:backend:issuer:v0.0.86";

const walletIssuerSigningSecret =
  parsed.WALLET_ISSUER_SIGNING_SECRET || "iland-backend-wallet-issuer-dev-secret";
const verifiedIdentityPepper =
  parsed.VERIFIED_IDENTITY_PEPPER || "iland-backend-verified-identity-dev-pepper";
const supabaseEnabled = Boolean(parsed.SUPABASE_URL && parsed.SUPABASE_SERVICE_ROLE_KEY);
const pollMapRefreshWorkerEnabled =
  (parsed.POLL_MAP_REFRESH_WORKER_ENABLED !== undefined
    ? toBoolean(parsed.POLL_MAP_REFRESH_WORKER_ENABLED)
    : true) && supabaseEnabled;
const pollMapRefreshIntervalMs = parsed.POLL_MAP_REFRESH_INTERVAL_MS || 10_000;
const pollMapRefreshPendingThreshold =
  parsed.POLL_MAP_REFRESH_PENDING_THRESHOLD || 10;
const pollMapRefreshMaxDelayMs = parsed.POLL_MAP_REFRESH_MAX_DELAY_MS || 60_000;
const pollMapRefreshMaxPollsPerCycle =
  parsed.POLL_MAP_REFRESH_MAX_POLLS_PER_CYCLE || 20;
const pollMapRefreshFailureCooldownMs =
  parsed.POLL_MAP_REFRESH_FAILURE_COOLDOWN_MS || 120_000;
const mapEnableAllPollsDebug =
  parsed.MAP_ENABLE_ALL_POLLS_DEBUG !== undefined
    ? toBoolean(parsed.MAP_ENABLE_ALL_POLLS_DEBUG)
    : false;
const solanaAuditCluster =
  parsed.SOLANA_AUDIT_CLUSTER || SHOLAN_TOKEN_DEFAULTS.cluster;
const solanaAuditTokenMint =
  parsed.SOLANA_AUDIT_TOKEN_MINT || SHOLAN_TOKEN_DEFAULTS.mint;
const solanaAuditTokenProgram =
  parsed.SOLANA_AUDIT_TOKEN_PROGRAM || SHOLAN_TOKEN_DEFAULTS.tokenProgram;
const solanaAuditProgramId =
  parsed.SOLANA_AUDIT_PROGRAM_ID || CIVICOS_AUDIT_PROGRAM_ID;
const solanaAuditDefaultFeeMode =
  parsed.SOLANA_AUDIT_DEFAULT_FEE_MODE || DEFAULT_SOLANA_AUDIT_FEE_MODE;
const solanaAuditSponsorshipEnabled =
  parsed.SOLANA_AUDIT_SPONSORSHIP_ENABLED !== undefined
    ? toBoolean(parsed.SOLANA_AUDIT_SPONSORSHIP_ENABLED)
    : true;
const solanaAuditUserPaidFeesEnabled =
  parsed.SOLANA_AUDIT_USER_PAID_FEES_ENABLED !== undefined
    ? toBoolean(parsed.SOLANA_AUDIT_USER_PAID_FEES_ENABLED)
    : false;
const solanaAuditTransactionsEnabled =
  parsed.SOLANA_AUDIT_TRANSACTIONS_ENABLED !== undefined
    ? toBoolean(parsed.SOLANA_AUDIT_TRANSACTIONS_ENABLED)
    : false;
const solanaAuditMainnetConfirmed =
  parsed.SOLANA_AUDIT_MAINNET_CONFIRMED !== undefined
    ? toBoolean(parsed.SOLANA_AUDIT_MAINNET_CONFIRMED)
    : false;
const solanaAuditRootPublisherPublicKey =
  parsed.SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY ??
  parsed.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY ??
  null;
const solanaAuditRootPublisherCustody =
  parsed.SOLANA_AUDIT_ROOT_PUBLISHER_CUSTODY ??
  (solanaAuditRootPublisherPublicKey &&
  parsed.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY &&
  solanaAuditRootPublisherPublicKey !== parsed.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY
    ? "external_kms_hsm_or_multisig_signing_service"
    : "backend_fee_payer_devnet");
const solanaAuditProgramUpgradeAuthorityCustody =
  parsed.SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY_CUSTODY ??
  "developer_wallet";
const zkpGroth16VoteVerifierEnabled =
  parsed.ZKP_GROTH16_VOTE_VERIFIER_ENABLED !== undefined
    ? toBoolean(parsed.ZKP_GROTH16_VOTE_VERIFIER_ENABLED)
    : false;
const zkpGroth16TallyVerifierEnabled =
  parsed.ZKP_GROTH16_TALLY_VERIFIER_ENABLED !== undefined
    ? toBoolean(parsed.ZKP_GROTH16_TALLY_VERIFIER_ENABLED)
    : false;
const zkpBallotCustodyMode =
  parsed.ZKP_BALLOT_CUSTODY_MODE ?? OPERATOR_TRUSTED_PRIVATE_BETA_CUSTODY_MODE;
const zkpPublicSecretBallotClaimsEnabled =
  parsed.ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED !== undefined
    ? toBoolean(parsed.ZKP_PUBLIC_SECRET_BALLOT_CLAIMS_ENABLED)
    : false;
const zkpLiveProvisionalResultsEnabled =
  parsed.ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED !== undefined
    ? toBoolean(parsed.ZKP_LIVE_PROVISIONAL_RESULTS_ENABLED)
    : zkpBallotCustodyMode !== THRESHOLD_TRUSTEE_CUSTODY_MODE;
const zkpReleaseChannel = parsed.ZKP_RELEASE_CHANNEL ?? "private_beta";
const zkpArtifactReleaseStage =
  parsed.ZKP_ARTIFACT_RELEASE_STAGE ?? "internal_rc";
const zkpPublicDevnetV01Confirmed =
  parsed.ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED !== undefined
    ? toBoolean(parsed.ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED)
    : false;
const zkpTallyProverMode = parsed.ZKP_TALLY_PROVER_MODE ?? "inline";
const zkpTallyWorkerEnabled =
  parsed.ZKP_TALLY_WORKER_ENABLED !== undefined
    ? toBoolean(parsed.ZKP_TALLY_WORKER_ENABLED)
    : false;
const zkpTallyWorkerConcurrency = parsed.ZKP_TALLY_WORKER_CONCURRENCY ?? 1;
const zkpTallyWorkerPollIntervalMs =
  parsed.ZKP_TALLY_WORKER_POLL_INTERVAL_MS ?? 5_000;
const zkpTallyWorkerLockTimeoutMs =
  parsed.ZKP_TALLY_WORKER_LOCK_TIMEOUT_MS ?? 600_000;
const zkpTallyWorkerMaxAttempts = parsed.ZKP_TALLY_WORKER_MAX_ATTEMPTS ?? 3;
const zkpTallyWorkerRetryDelayMs =
  parsed.ZKP_TALLY_WORKER_RETRY_DELAY_MS ?? 60_000;
const zkpTallyWorkerHeartbeatStaleMs =
  parsed.ZKP_TALLY_WORKER_HEARTBEAT_STALE_MS ?? 120_000;
const zkpTallyWorkerRequiredForProduction =
  parsed.ZKP_TALLY_WORKER_REQUIRED_FOR_PRODUCTION !== undefined
    ? toBoolean(parsed.ZKP_TALLY_WORKER_REQUIRED_FOR_PRODUCTION)
    : false;
const normalizeHex64Env = (value: string | undefined): string | null =>
  value ? value.trim().toLowerCase() : null;

export const env = Object.freeze({
  nodeEnv: parsed.NODE_ENV,
  host: parsed.HOST,
  port: parsed.PORT,
  supabase: Object.freeze({
    enabled: supabaseEnabled,
    url: parsed.SUPABASE_URL ?? null,
    serviceRoleKey: parsed.SUPABASE_SERVICE_ROLE_KEY ?? null,
    projectRef: parsed.SUPABASE_PROJECT_REF ?? null,
  }),
  auth: Object.freeze({
    issuer: authIssuer,
    accessTokenTtlSeconds: authAccessTokenTtlSeconds,
    refreshTokenTtlDays: authRefreshTokenTtlDays,
    maxActiveSessionsPerUser: authMaxActiveSessionsPerUser,
    requireAttestedSessionsForProtectedRoutes:
      authRequireAttestedSessionsForProtectedRoutes,
    enableTransitionalCryptoBypass: authEnableTransitionalCryptoBypass,
    iosTeamId: authIosTeamId,
    iosBundleId: authIosBundleId,
    androidPackageName: authAndroidPackageName,
    iosAppAttestEnvironment: authIosAppAttestEnvironment,
    androidAllowedSigningCertDigests: authAndroidAllowedSigningCertDigests,
    androidGoogleApiKey: authAndroidGoogleApiKey,
    androidGoogleServiceAccountJson: authAndroidGoogleServiceAccountJson,
    androidGoogleServiceAccountClientEmail:
      authAndroidGoogleServiceAccountClientEmail,
    androidGoogleServiceAccountPrivateKey:
      authAndroidGoogleServiceAccountPrivateKey,
    androidRequireStrongIntegrity: authAndroidRequireStrongIntegrity,
  }),
  wallet: Object.freeze({
    issuerId: walletIssuerId,
    issuerSigningSecret: walletIssuerSigningSecret,
  }),
  verifiedIdentity: Object.freeze({
    pepper: verifiedIdentityPepper,
  }),
  openai: Object.freeze({
    apiKeyConfigured: Boolean(parsed.OPENAI_API_KEY),
  }),
  pollMapRefreshWorker: Object.freeze({
    enabled: pollMapRefreshWorkerEnabled,
    intervalMs: pollMapRefreshIntervalMs,
    pendingVoteThreshold: pollMapRefreshPendingThreshold,
    maxDelayMs: pollMapRefreshMaxDelayMs,
    maxPollsPerCycle: pollMapRefreshMaxPollsPerCycle,
    failureCooldownMs: pollMapRefreshFailureCooldownMs,
  }),
  map: Object.freeze({
    enableAllPollsDebug: mapEnableAllPollsDebug,
  }),
  solanaAudit: Object.freeze({
    cluster: solanaAuditCluster,
    rpcUrl: parsed.SOLANA_AUDIT_RPC_URL ?? null,
    programId: solanaAuditProgramId,
    tokenMint: solanaAuditTokenMint,
    tokenProgram: solanaAuditTokenProgram,
    tokenSymbol: SHOLAN_TOKEN_DEFAULTS.symbol,
    tokenDecimals: SHOLAN_TOKEN_DEFAULTS.decimals,
    registryAuthority: parsed.SOLANA_AUDIT_REGISTRY_AUTHORITY ?? null,
    rootPublisherPublicKey: solanaAuditRootPublisherPublicKey,
    rootPublisherCustody: solanaAuditRootPublisherCustody,
    programUpgradeAuthority:
      parsed.SOLANA_AUDIT_PROGRAM_UPGRADE_AUTHORITY ?? null,
    programUpgradeAuthorityCustody:
      solanaAuditProgramUpgradeAuthorityCustody,
    treasury: parsed.SOLANA_AUDIT_TREASURY ?? null,
    feePayerPublicKey: parsed.SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY ?? null,
    feePayerSecretKey: parsed.SOLANA_AUDIT_FEE_PAYER_SECRET_KEY ?? null,
    defaultFeeMode: solanaAuditDefaultFeeMode,
    sponsorshipEnabled: solanaAuditSponsorshipEnabled,
    userPaidFeesEnabled: solanaAuditUserPaidFeesEnabled,
    mainnetConfirmed: solanaAuditMainnetConfirmed,
    networkFeeCurrency: "SOL",
    baseFeeLamportsPerSignature: SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
    tokenRequiredForBackendProcessing: false,
    transactionsEnabled: solanaAuditTransactionsEnabled,
  }),
  zkp: Object.freeze({
    release: Object.freeze({
      channel: zkpReleaseChannel,
      artifactStage: zkpArtifactReleaseStage,
      publicDevnetV01Confirmed: zkpPublicDevnetV01Confirmed,
      publicDevnetVersion: "0.1",
      futureMainnetRequiresNewReleaseDecision: true,
    }),
    ballotCustody: Object.freeze({
      mode: zkpBallotCustodyMode,
      publicSecretBallotClaimsEnabled: zkpPublicSecretBallotClaimsEnabled,
      liveProvisionalResultsEnabled: zkpLiveProvisionalResultsEnabled,
    }),
    tallyWorker: Object.freeze({
      proverMode: zkpTallyProverMode,
      enabled: zkpTallyWorkerEnabled,
      workerId: parsed.ZKP_TALLY_WORKER_ID ?? null,
      concurrency: zkpTallyWorkerConcurrency,
      pollIntervalMs: zkpTallyWorkerPollIntervalMs,
      lockTimeoutMs: zkpTallyWorkerLockTimeoutMs,
      maxAttempts: zkpTallyWorkerMaxAttempts,
      retryDelayMs: zkpTallyWorkerRetryDelayMs,
      heartbeatStaleMs: zkpTallyWorkerHeartbeatStaleMs,
      requiredForProduction: zkpTallyWorkerRequiredForProduction,
    }),
    groth16: Object.freeze({
      voteVerifierEnabled: zkpGroth16VoteVerifierEnabled,
      voteCircuitId: parsed.ZKP_GROTH16_VOTE_CIRCUIT_ID ?? null,
      voteVerifierKeyHash: normalizeHex64Env(
        parsed.ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH,
      ),
      publicInputSchemaVersion:
        parsed.ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION ??
        parsed.ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION ??
        null,
      trustedSetupTranscriptHash: normalizeHex64Env(
        parsed.ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH ??
          parsed.ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH,
      ),
      voteArtifactManifestPath:
        parsed.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH ?? null,
      voteArtifactManifestHash: normalizeHex64Env(
        parsed.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH,
      ),
      tallyVerifierEnabled: zkpGroth16TallyVerifierEnabled,
      tallyCircuitId: parsed.ZKP_GROTH16_TALLY_CIRCUIT_ID ?? null,
      tallyVerifierKeyHash: normalizeHex64Env(
        parsed.ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH,
      ),
      tallyPublicInputSchemaVersion:
        parsed.ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION ?? null,
      tallyTrustedSetupTranscriptHash: normalizeHex64Env(
        parsed.ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH,
      ),
      tallyArtifactManifestPath:
        parsed.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH ?? null,
      tallyArtifactManifestHash: normalizeHex64Env(
        parsed.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH,
      ),
    }),
  }),
});

export default env;
