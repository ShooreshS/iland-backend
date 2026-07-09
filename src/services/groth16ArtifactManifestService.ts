import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";

import { z } from "zod";

import type { JsonValue } from "../types/json";
import { canonicalizeJson } from "./pollPolicyService";

export const GROTH16_ARTIFACT_MANIFEST_VERSION =
  "civicos-groth16-artifact-manifest-v1" as const;
export const GROTH16_VERIFIER_KEY_REGISTRY_VERSION =
  "civicos-groth16-verifier-key-registry-v1" as const;
export const GROTH16_ARTIFACT_MANIFEST_DOMAIN =
  "org.civicos.zkp.groth16.artifact-manifest" as const;

const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

const hex64Schema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(HEX_64_PATTERN, "Expected a 32-byte lowercase hex hash.");

const nonEmptyStringSchema = z.string().trim().min(1);

const artifactRoleSchema = z.enum([
  "verification_key",
  "proving_key",
  "witness_wasm",
  "native_prover",
  "r1cs",
  "metadata",
]);

const artifactFormatSchema = z.enum([
  "snarkjs-vkey-json",
  "zkey",
  "wasm",
  "native-ios-xcframework",
  "native-android-aar",
  "r1cs",
  "json",
  "other",
]);

const artifactEntrySchema = z
  .object({
    role: artifactRoleSchema,
    path: nonEmptyStringSchema,
    sha256: hex64Schema,
    format: artifactFormatSchema.optional(),
    bytes: z.number().int().positive().optional(),
  })
  .strict();

const trustedSetupSchema = z
  .object({
    ceremony: nonEmptyStringSchema.optional(),
    phase1TranscriptHash: hex64Schema.optional(),
    phase2TranscriptHash: hex64Schema.optional(),
    contributionCount: z.number().int().nonnegative().optional(),
    notes: nonEmptyStringSchema.optional(),
  })
  .strict();

const circuitParametersSchema = z
  .object({
    credentialMerkleDepth: z.number().int().positive().optional(),
    tallyBatchSize: z.number().int().positive().optional(),
    maxOptions: z.number().int().positive().optional(),
  })
  .strict();

export const groth16ArtifactManifestSchema = z
  .object({
    version: z.literal(GROTH16_ARTIFACT_MANIFEST_VERSION),
    artifactKind: z.enum(["vote", "tally"]),
    circuitId: nonEmptyStringSchema,
    proofSystem: z.literal("groth16"),
    protocol: z.literal("groth16"),
    curve: z.literal("bn254"),
    hashSuite: z.literal("poseidon-bn254-v1"),
    publicInputSchemaVersion: nonEmptyStringSchema,
    trustedSetupTranscriptHash: hex64Schema,
    verifierKeyHash: hex64Schema,
    provingKeyHash: hex64Schema,
    wasmOrNativeArtifactHash: hex64Schema,
    circuitParameters: circuitParametersSchema,
    artifacts: z.array(artifactEntrySchema).min(3),
    trustedSetup: trustedSetupSchema.optional(),
    generatedAt: nonEmptyStringSchema.optional(),
    notes: nonEmptyStringSchema.optional(),
  })
  .strict()
  .superRefine((manifest, context) => {
    const hasVerifierKey = manifest.artifacts.some(
      (artifact) =>
        artifact.role === "verification_key" &&
        artifact.sha256 === manifest.verifierKeyHash,
    );
    if (!hasVerifierKey) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "artifacts must include a verification_key entry whose sha256 matches verifierKeyHash.",
        path: ["artifacts"],
      });
    }

    const hasProvingKey = manifest.artifacts.some(
      (artifact) =>
        artifact.role === "proving_key" &&
        artifact.sha256 === manifest.provingKeyHash,
    );
    if (!hasProvingKey) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "artifacts must include a proving_key entry whose sha256 matches provingKeyHash.",
        path: ["artifacts"],
      });
    }

    const hasMobileProverArtifact = manifest.artifacts.some(
      (artifact) =>
        (artifact.role === "witness_wasm" ||
          artifact.role === "native_prover") &&
        artifact.sha256 === manifest.wasmOrNativeArtifactHash,
    );
    if (!hasMobileProverArtifact) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "artifacts must include a witness_wasm or native_prover entry whose sha256 matches wasmOrNativeArtifactHash.",
        path: ["artifacts"],
      });
    }
  });

export type Groth16ArtifactKind = "vote" | "tally";
export type Groth16ArtifactManifest = z.infer<
  typeof groth16ArtifactManifestSchema
>;

export type Groth16VerifierKeyRegistryRecord = Readonly<{
  version: typeof GROTH16_VERIFIER_KEY_REGISTRY_VERSION;
  artifactKind: Groth16ArtifactKind;
  proofSystem: "groth16";
  protocol: "groth16";
  curve: "bn254";
  hashSuite: "poseidon-bn254-v1";
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
  trustedSetupTranscriptHash: string;
  artifactManifestHash: string;
}>;

export type Groth16ArtifactManifestValidationResult =
  | {
      ok: true;
      manifest: Groth16ArtifactManifest;
      manifestHash: string;
      registryRecord: Groth16VerifierKeyRegistryRecord;
    }
  | {
      ok: false;
      reason:
        | "MANIFEST_INVALID"
        | "MANIFEST_HASH_MISMATCH"
        | "ARTIFACT_KIND_MISMATCH"
        | "ARTIFACT_FILE_UNREADABLE"
        | "ARTIFACT_FILE_HASH_MISMATCH"
        | "CONSTRAINT_MISMATCH";
      message: string;
    };

export type Groth16ArtifactManifestFileLoadResult =
  | (Extract<Groth16ArtifactManifestValidationResult, { ok: true }> & {
      manifestPath: string;
    })
  | Extract<Groth16ArtifactManifestValidationResult, { ok: false }>;

export type Groth16ArtifactManifestConstraints = Partial<{
  artifactKind: Groth16ArtifactKind;
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
  trustedSetupTranscriptHash: string;
  hashSuite: "poseidon-bn254-v1";
  protocol: "groth16";
  circuitParameters: Partial<Groth16ArtifactManifest["circuitParameters"]>;
}>;

const sha256Hex = (value: string | Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");

const formatZodIssues = (error: z.ZodError): string =>
  error.issues
    .map((issue) => {
      const path = issue.path.length > 0 ? `${issue.path.join(".")}: ` : "";
      return `${path}${issue.message}`;
    })
    .join("; ");

export const hashGroth16ArtifactManifest = (
  manifest: Groth16ArtifactManifest,
): string =>
  sha256Hex(
    `${GROTH16_ARTIFACT_MANIFEST_DOMAIN}|${canonicalizeJson(
      manifest as unknown as JsonValue,
    )}`,
  );

export const buildGroth16VerifierKeyRegistryRecord = (
  manifest: Groth16ArtifactManifest,
  manifestHash = hashGroth16ArtifactManifest(manifest),
): Groth16VerifierKeyRegistryRecord =>
  Object.freeze({
    version: GROTH16_VERIFIER_KEY_REGISTRY_VERSION,
    artifactKind: manifest.artifactKind,
    proofSystem: manifest.proofSystem,
    protocol: manifest.protocol,
    curve: manifest.curve,
    hashSuite: manifest.hashSuite,
    circuitId: manifest.circuitId,
    verifierKeyHash: manifest.verifierKeyHash,
    publicInputSchemaVersion: manifest.publicInputSchemaVersion,
    trustedSetupTranscriptHash: manifest.trustedSetupTranscriptHash,
    artifactManifestHash: manifestHash,
  });

export const parseGroth16ArtifactManifest = (
  input: unknown,
): Groth16ArtifactManifestValidationResult => {
  const parsed = groth16ArtifactManifestSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      reason: "MANIFEST_INVALID",
      message: formatZodIssues(parsed.error),
    };
  }

  const manifest = parsed.data;
  const manifestHash = hashGroth16ArtifactManifest(manifest);
  return {
    ok: true,
    manifest,
    manifestHash,
    registryRecord: buildGroth16VerifierKeyRegistryRecord(
      manifest,
      manifestHash,
    ),
  };
};

export const validateGroth16ArtifactManifestConstraints = (
  manifest: Groth16ArtifactManifest,
  constraints: Groth16ArtifactManifestConstraints,
): Groth16ArtifactManifestValidationResult => {
  const mismatches = Object.entries(constraints)
    .filter(([key]) => key !== "circuitParameters")
    .filter(([, expected]) => typeof expected === "string" && expected.length > 0)
    .filter(([key, expected]) => {
      const actual = manifest[key as keyof Groth16ArtifactManifest];
      return actual !== expected;
    })
    .map(([key, expected]) => `${key}=${String(expected)}`);

  const circuitParameterMismatches = Object.entries(
    constraints.circuitParameters ?? {},
  )
    .filter(([, expected]) => typeof expected === "number")
    .filter(([key, expected]) => {
      const actual =
        manifest.circuitParameters[
          key as keyof Groth16ArtifactManifest["circuitParameters"]
        ];
      return actual !== expected;
    })
    .map(([key, expected]) => `circuitParameters.${key}=${String(expected)}`);

  mismatches.push(...circuitParameterMismatches);

  if (mismatches.length > 0) {
    return {
      ok: false,
      reason: "CONSTRAINT_MISMATCH",
      message: `Groth16 artifact manifest does not match expected ${mismatches.join(
        ", ",
      )}.`,
    };
  }

  const manifestHash = hashGroth16ArtifactManifest(manifest);
  return {
    ok: true,
    manifest,
    manifestHash,
    registryRecord: buildGroth16VerifierKeyRegistryRecord(
      manifest,
      manifestHash,
    ),
  };
};

export const loadGroth16ArtifactManifestFile = (params: {
  manifestPath: string;
  expectedManifestHash?: string | null;
  expectedArtifactKind?: Groth16ArtifactKind | null;
  verifyLocalArtifacts?: boolean;
}): Groth16ArtifactManifestFileLoadResult => {
  const manifestPath = isAbsolute(params.manifestPath)
    ? params.manifestPath
    : resolve(process.cwd(), params.manifestPath);

  let manifestJson: unknown;
  try {
    manifestJson = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    return {
      ok: false,
      reason: "MANIFEST_INVALID",
      message:
        error instanceof Error
          ? error.message
          : "Groth16 artifact manifest could not be parsed.",
    };
  }

  const parsed = parseGroth16ArtifactManifest(manifestJson);
  if (!parsed.ok) {
    return parsed;
  }

  const expectedManifestHash = params.expectedManifestHash?.trim().toLowerCase();
  if (
    expectedManifestHash &&
    expectedManifestHash !== parsed.manifestHash
  ) {
    return {
      ok: false,
      reason: "MANIFEST_HASH_MISMATCH",
      message: "Groth16 artifact manifest hash does not match the pinned hash.",
    };
  }

  if (
    params.expectedArtifactKind &&
    parsed.manifest.artifactKind !== params.expectedArtifactKind
  ) {
    return {
      ok: false,
      reason: "ARTIFACT_KIND_MISMATCH",
      message: `Groth16 artifact manifest kind is ${parsed.manifest.artifactKind}, expected ${params.expectedArtifactKind}.`,
    };
  }

  if (params.verifyLocalArtifacts) {
    const manifestDir = dirname(manifestPath);
    for (const artifact of parsed.manifest.artifacts) {
      const artifactPath = isAbsolute(artifact.path)
        ? artifact.path
        : resolve(manifestDir, artifact.path);

      let artifactBytes: Uint8Array;
      try {
        artifactBytes = readFileSync(artifactPath);
      } catch (error) {
        return {
          ok: false,
          reason: "ARTIFACT_FILE_UNREADABLE",
          message:
            error instanceof Error
              ? error.message
              : `Groth16 artifact file could not be read: ${artifact.path}`,
        };
      }

      const actualHash = sha256Hex(artifactBytes);
      if (actualHash !== artifact.sha256) {
        return {
          ok: false,
          reason: "ARTIFACT_FILE_HASH_MISMATCH",
          message: `Groth16 artifact file hash mismatch for ${artifact.path}.`,
        };
      }
    }
  }

  return {
    ...parsed,
    manifestPath,
  };
};

export default {
  GROTH16_ARTIFACT_MANIFEST_VERSION,
  GROTH16_VERIFIER_KEY_REGISTRY_VERSION,
  buildGroth16VerifierKeyRegistryRecord,
  groth16ArtifactManifestSchema,
  hashGroth16ArtifactManifest,
  loadGroth16ArtifactManifestFile,
  parseGroth16ArtifactManifest,
  validateGroth16ArtifactManifestConstraints,
};
