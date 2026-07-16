import { createHash } from "node:crypto";

import {
  DEFAULT_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH,
  DEFAULT_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH,
  DEFAULT_GROTH16_TALLY_CIRCUIT_ID,
  DEFAULT_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  DEFAULT_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH,
  DEFAULT_GROTH16_TALLY_VERIFIER_KEY_HASH,
} from "../config/zkpGroth16ArtifactDefaults";
import type { PollRow } from "../types/db";
import type { JsonValue } from "../types/json";
import {
  loadGroth16ArtifactManifestFile,
  validateGroth16ArtifactManifestConstraints,
  type Groth16ArtifactManifest,
  type Groth16VerifierKeyRegistryRecord,
} from "./groth16ArtifactManifestService";
import {
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
  CIVIC_PRODUCTION_PROOF_PROTOCOL,
  CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
} from "./groth16ProofVerifierService";
import {
  encodeGroth16PublicField,
  verifyGroth16ProofFromManifestWithSnarkjs,
} from "./groth16SnarkjsVerifierEngine";
import { canonicalizeJson } from "./pollPolicyService";
import { poseidonHashHex64 } from "./poseidonBn254Service";

export const CIVIC_TALLY_PROOF_ENVELOPE_VERSION =
  "civicos-groth16-tally-proof-envelope-v1" as const;
export const CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION =
  "civicos-groth16-tally-public-inputs-v1" as const;
export const CIVIC_TALLY_MAX_VOTES = 64 as const;
export const CIVIC_TALLY_MAX_OPTIONS = 8 as const;

const CIVIC_ZKP_DOMAIN = "org.civicos.zkp" as const;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

export const GROTH16_TALLY_PUBLIC_SIGNAL_ORDER = Object.freeze([
  "pollId",
  "pollPolicyHash",
  "credentialSchemaHash",
  "optionSetHash",
  "optionCount",
  "nullifierRoot",
  "voteCommitmentRoot",
  "encryptedVoteRoot",
  "acceptedVoteCount",
  "optionCountsHash",
] as const);

export type Groth16TallyOptionResultDto = {
  optionId: string;
  count: number;
};

export type Groth16TallyPublicInputsDto = {
  version: string;
  pollId: string;
  pollPolicyHash: string;
  credentialSchemaHash: string;
  optionSetHash: string;
  optionCount: number;
  nullifierRoot: string;
  voteCommitmentRoot: string;
  encryptedVoteRoot: string;
  acceptedVoteCount: number;
  optionResults: Groth16TallyOptionResultDto[];
  optionCountsHash: string;
  proofSystemVersion: string;
  hashSuite: string;
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
};

export type Groth16TallyProofEnvelopeDto = {
  version: string;
  protocol: string;
  proofSystemVersion: string;
  status: string;
  hashSuite: string;
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
  proof: JsonValue;
  publicInputs: Groth16TallyPublicInputsDto;
  publicInputsHash: string;
};

export type Groth16TallyVerifierConfig = {
  tallyVerifierEnabled: boolean;
  tallyCircuitId: string | null;
  tallyVerifierKeyHash: string | null;
  tallyPublicInputSchemaVersion: string | null;
  tallyTrustedSetupTranscriptHash: string | null;
  tallyArtifactManifestPath: string | null;
  tallyArtifactManifestHash: string | null;
  tallyArtifactManifest: Groth16ArtifactManifest | null;
  tallyArtifactManifestStatus:
    | "not_configured"
    | "loaded"
    | "invalid"
    | "hash_mismatch"
    | "kind_mismatch"
    | "config_mismatch";
  tallyArtifactManifestError: string | null;
  tallyVerifierKeyRegistryRecord: Groth16VerifierKeyRegistryRecord | null;
};

export type VerifiedGroth16TallyProofAuditMaterial = {
  resultHash: string;
  tallyProofHash: string;
  tallyPublicInputsHash: string;
  tallyVerifierKeyHash: string;
  tallyCircuitId: string;
  nullifierRoot: string;
  voteCommitmentRoot: string;
  encryptedVoteRoot: string;
  acceptedCount: number;
  proofEnvelopeJson: Groth16TallyProofEnvelopeDto;
};

export type Groth16TallyProofVerificationResult =
  | {
      ok: true;
      auditMaterial: VerifiedGroth16TallyProofAuditMaterial;
    }
  | {
      ok: false;
      reason:
        | "PROOF_REQUIRED"
        | "PROOF_INVALID"
        | "POLL_POLICY_HASH_MISMATCH"
        | "CREDENTIAL_SCHEMA_HASH_MISMATCH"
        | "OPTION_SET_HASH_MISMATCH"
        | "ROOT_MISMATCH"
        | "CIRCUIT_ID_MISMATCH"
        | "VERIFIER_KEY_MISMATCH"
        | "VERIFIER_DISABLED"
        | "VERIFIER_UNCONFIGURED"
        | "VERIFIER_REJECTED";
      message: string;
    };

export type Groth16TallyProofVerifierDependencies = {
  config?: Groth16TallyVerifierConfig;
  verifyProof?: ((input: {
    proof: JsonValue;
    publicInputs: Groth16TallyPublicInputsDto;
    publicSignals: string[];
    artifactManifest: Groth16ArtifactManifest;
    artifactManifestPath: string | null;
    artifactManifestHash: string;
    verifierKeyHash: string;
  }) => boolean | Promise<boolean>) | null;
};

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

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

const normalizeHex64 = (value: string | null | undefined): string | null => {
  const normalized =
    typeof value === "string" ? stripWrappingQuotes(value).toLowerCase() : "";
  return HEX_64_PATTERN.test(normalized) ? normalized : null;
};

const normalizeOptionalString = (value: string | undefined): string | null => {
  const normalized =
    typeof value === "string" ? stripWrappingQuotes(value).trim() : "";
  return normalized.length > 0 ? normalized : null;
};

const toBoolean = (value: string | undefined): boolean => {
  const normalized =
    typeof value === "string" ? stripWrappingQuotes(value).toLowerCase() : "";
  return normalized === "1" || normalized === "true" || normalized === "yes";
};

const missingArtifactManifestConfig = (
  values: Pick<
    Groth16TallyVerifierConfig,
    | "tallyVerifierEnabled"
    | "tallyCircuitId"
    | "tallyVerifierKeyHash"
    | "tallyPublicInputSchemaVersion"
    | "tallyTrustedSetupTranscriptHash"
  >,
): Groth16TallyVerifierConfig => ({
  ...values,
  tallyArtifactManifestPath: null,
  tallyArtifactManifestHash: null,
  tallyArtifactManifest: null,
  tallyArtifactManifestStatus: "not_configured",
  tallyArtifactManifestError: null,
  tallyVerifierKeyRegistryRecord: null,
});

const loadTallyArtifactManifestFromEnv = (values: {
  tallyVerifierEnabled: boolean;
  tallyCircuitId: string | null;
  tallyVerifierKeyHash: string | null;
  tallyPublicInputSchemaVersion: string | null;
  tallyTrustedSetupTranscriptHash: string | null;
}): Groth16TallyVerifierConfig => {
  const tallyArtifactManifestPath = normalizeOptionalString(
    process.env.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH ??
      DEFAULT_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH,
  );
  const tallyArtifactManifestHash = normalizeHex64(
    process.env.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH ??
      DEFAULT_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH,
  );

  if (!tallyArtifactManifestPath) {
    return missingArtifactManifestConfig(values);
  }

  if (!tallyArtifactManifestHash) {
    return {
      ...values,
      tallyArtifactManifestPath,
      tallyArtifactManifestHash,
      tallyArtifactManifest: null,
      tallyArtifactManifestStatus: "invalid",
      tallyArtifactManifestError:
        "Groth16 tally artifact manifest hash must be pinned.",
      tallyVerifierKeyRegistryRecord: null,
    };
  }

  const loaded = loadGroth16ArtifactManifestFile({
    manifestPath: tallyArtifactManifestPath,
    expectedManifestHash: tallyArtifactManifestHash,
    expectedArtifactKind: "tally",
  });

  if (!loaded.ok) {
    const status =
      loaded.reason === "MANIFEST_HASH_MISMATCH"
        ? "hash_mismatch"
        : loaded.reason === "ARTIFACT_KIND_MISMATCH"
          ? "kind_mismatch"
          : "invalid";
    return {
      ...values,
      tallyArtifactManifestPath,
      tallyArtifactManifestHash,
      tallyArtifactManifest: null,
      tallyArtifactManifestStatus: status,
      tallyArtifactManifestError: loaded.message,
      tallyVerifierKeyRegistryRecord: null,
    };
  }

  const tallyCircuitId = values.tallyCircuitId ?? loaded.manifest.circuitId;
  const tallyVerifierKeyHash =
    values.tallyVerifierKeyHash ?? loaded.manifest.verifierKeyHash;
  const tallyPublicInputSchemaVersion =
    values.tallyPublicInputSchemaVersion ??
    loaded.manifest.publicInputSchemaVersion;
  const tallyTrustedSetupTranscriptHash =
    values.tallyTrustedSetupTranscriptHash ??
    loaded.manifest.trustedSetupTranscriptHash;

  const constraints = validateGroth16ArtifactManifestConstraints(
    loaded.manifest,
    {
      artifactKind: "tally",
      circuitId: tallyCircuitId,
      verifierKeyHash: tallyVerifierKeyHash,
      publicInputSchemaVersion: tallyPublicInputSchemaVersion,
      trustedSetupTranscriptHash: tallyTrustedSetupTranscriptHash,
      hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
      protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
      circuitParameters: {
        tallyBatchSize: CIVIC_TALLY_MAX_VOTES,
        maxOptions: CIVIC_TALLY_MAX_OPTIONS,
      },
    },
  );

  if (!constraints.ok) {
    return {
      ...values,
      tallyArtifactManifestPath,
      tallyArtifactManifestHash,
      tallyArtifactManifest: loaded.manifest,
      tallyArtifactManifestStatus: "config_mismatch",
      tallyArtifactManifestError: constraints.message,
      tallyVerifierKeyRegistryRecord: null,
    };
  }

  return {
    tallyVerifierEnabled: values.tallyVerifierEnabled,
    tallyCircuitId,
    tallyVerifierKeyHash,
    tallyPublicInputSchemaVersion,
    tallyTrustedSetupTranscriptHash,
    tallyArtifactManifestPath,
    tallyArtifactManifestHash: loaded.manifestHash,
    tallyArtifactManifest: loaded.manifest,
    tallyArtifactManifestStatus: "loaded",
    tallyArtifactManifestError: null,
    tallyVerifierKeyRegistryRecord: loaded.registryRecord,
  };
};

export const hashGroth16TallyOptionCounts = (
  optionResults: readonly Groth16TallyOptionResultDto[],
): Promise<string> =>
  poseidonHashHex64([
    1201,
    ...Array.from({ length: CIVIC_TALLY_MAX_OPTIONS }, (_, index) =>
      Math.max(0, Math.trunc(optionResults[index]?.count ?? 0)),
    ),
  ]);

export const hashGroth16TallyPublicInputs = (
  publicInputs: Groth16TallyPublicInputsDto,
): string =>
  sha256Hex(
    `${CIVIC_ZKP_DOMAIN}|groth16-tally-public-inputs|${canonicalizeJson(publicInputs)}`,
  );

export const hashGroth16TallyProofEnvelope = (
  proof: Groth16TallyProofEnvelopeDto,
): string =>
  sha256Hex(
    `${CIVIC_ZKP_DOMAIN}|groth16-tally-proof-envelope|${canonicalizeJson(proof)}`,
  );

export const encodeGroth16TallyPublicSignals = (
  publicInputs: Groth16TallyPublicInputsDto,
): string[] =>
  GROTH16_TALLY_PUBLIC_SIGNAL_ORDER.map((name) =>
    encodeGroth16PublicField(
      name,
      name === "acceptedVoteCount"
        ? publicInputs.acceptedVoteCount
        : publicInputs[name],
    ),
  );

export const getGroth16TallyVerifierConfig = (): Groth16TallyVerifierConfig =>
  loadTallyArtifactManifestFromEnv({
    tallyVerifierEnabled: toBoolean(
      process.env.ZKP_GROTH16_TALLY_VERIFIER_ENABLED,
    ),
    tallyCircuitId: normalizeOptionalString(
      process.env.ZKP_GROTH16_TALLY_CIRCUIT_ID ??
        DEFAULT_GROTH16_TALLY_CIRCUIT_ID,
    ),
    tallyVerifierKeyHash: normalizeHex64(
      process.env.ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH ??
        DEFAULT_GROTH16_TALLY_VERIFIER_KEY_HASH,
    ),
    tallyPublicInputSchemaVersion: normalizeOptionalString(
      process.env.ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION ??
        DEFAULT_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    ),
    tallyTrustedSetupTranscriptHash: normalizeHex64(
      process.env.ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH ??
        DEFAULT_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH,
    ),
  });

export const isGroth16TallyVerifierConfigured = (
  config: Groth16TallyVerifierConfig = getGroth16TallyVerifierConfig(),
): boolean =>
  Boolean(
    config.tallyVerifierEnabled &&
      config.tallyCircuitId &&
      config.tallyVerifierKeyHash &&
      config.tallyPublicInputSchemaVersion &&
      config.tallyTrustedSetupTranscriptHash &&
      config.tallyArtifactManifestStatus === "loaded" &&
      config.tallyArtifactManifest &&
      config.tallyVerifierKeyRegistryRecord,
  );

const reject = (
  reason: Extract<Groth16TallyProofVerificationResult, { ok: false }>["reason"],
  message: string,
): Groth16TallyProofVerificationResult => ({
  ok: false,
  reason,
  message,
});

const normalizeOptionCount = (value: unknown): number | null => {
  const numeric =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value.trim())
        ? Number(value.trim())
        : NaN;
  if (
    !Number.isInteger(numeric) ||
    numeric < 1 ||
    numeric > CIVIC_TALLY_MAX_OPTIONS
  ) {
    return null;
  }
  return numeric;
};

const defaultVerifyProof: NonNullable<
  Groth16TallyProofVerifierDependencies["verifyProof"]
> = (input) =>
  verifyGroth16ProofFromManifestWithSnarkjs({
    proof: input.proof,
    publicSignals: input.publicSignals,
    artifactManifest: input.artifactManifest,
    artifactManifestPath: input.artifactManifestPath,
    artifactManifestHash: input.artifactManifestHash,
    verifierKeyHash: input.verifierKeyHash,
  });

export const verifyGroth16TallyProofForPoll = async (
  params: {
    poll: PollRow;
    proof?: Groth16TallyProofEnvelopeDto | null;
    nullifierRoot: string;
    voteCommitmentRoot: string;
    encryptedVoteRoot: string;
    acceptedVoteCount: number;
    expectedOptionIds: readonly string[];
  },
  dependencies: Groth16TallyProofVerifierDependencies = {},
): Promise<Groth16TallyProofVerificationResult> => {
  if (!params.proof) {
    return reject("PROOF_REQUIRED", "This poll requires a Groth16 tally proof.");
  }

  const config = dependencies.config ?? getGroth16TallyVerifierConfig();
  if (!config.tallyVerifierEnabled) {
    return reject(
      "VERIFIER_DISABLED",
      "Groth16 tally proof verification is disabled for this backend.",
    );
  }

  if (!isGroth16TallyVerifierConfigured(config)) {
    console.error("[zkp] Groth16 tally verifier is not fully configured", {
      enabled: config.tallyVerifierEnabled,
      circuitId: config.tallyCircuitId,
      verifierKeyHash: config.tallyVerifierKeyHash,
      publicInputSchemaVersion: config.tallyPublicInputSchemaVersion,
      trustedSetupTranscriptHash: config.tallyTrustedSetupTranscriptHash,
      artifactManifestPath: config.tallyArtifactManifestPath,
      artifactManifestHash: config.tallyArtifactManifestHash,
      artifactManifestStatus: config.tallyArtifactManifestStatus,
      artifactManifestError: config.tallyArtifactManifestError,
    });

    return reject(
      "VERIFIER_UNCONFIGURED",
      "Groth16 tally proof verification is enabled but verifier artifacts are not fully configured.",
    );
  }

  const artifactManifest = config.tallyArtifactManifest;
  const registryRecord = config.tallyVerifierKeyRegistryRecord;
  const artifactManifestHash = registryRecord?.artifactManifestHash || "";
  if (!artifactManifest || !registryRecord || !artifactManifestHash) {
    return reject(
      "VERIFIER_UNCONFIGURED",
      "Groth16 tally proof verification is enabled but the pinned artifact manifest is unavailable.",
    );
  }

  const proof = params.proof;
  if (
    proof.version !== CIVIC_TALLY_PROOF_ENVELOPE_VERSION ||
    proof.protocol !== CIVIC_PRODUCTION_PROOF_PROTOCOL ||
    proof.proofSystemVersion !== CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION ||
    proof.status !== CIVIC_PRODUCTION_PROOF_GENERATED_STATUS ||
    proof.hashSuite !== CIVIC_PRODUCTION_HASH_SUITE
  ) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof envelope uses an unsupported version.",
    );
  }

  const configuredCircuitId = config.tallyCircuitId || "";
  const configuredVerifierKeyHash = config.tallyVerifierKeyHash || "";
  const configuredPublicInputSchemaVersion =
    config.tallyPublicInputSchemaVersion || "";

  if (
    proof.circuitId !== configuredCircuitId ||
    proof.publicInputs.circuitId !== configuredCircuitId
  ) {
    return reject(
      "CIRCUIT_ID_MISMATCH",
      "Groth16 tally proof circuit id does not match the configured circuit.",
    );
  }

  if (
    proof.verifierKeyHash !== configuredVerifierKeyHash ||
    proof.publicInputs.verifierKeyHash !== configuredVerifierKeyHash
  ) {
    return reject(
      "VERIFIER_KEY_MISMATCH",
      "Groth16 tally proof verifier key hash does not match the configured verifier key.",
    );
  }

  if (
    proof.publicInputSchemaVersion !== configuredPublicInputSchemaVersion ||
    proof.publicInputs.version !== configuredPublicInputSchemaVersion ||
    proof.publicInputs.publicInputSchemaVersion !==
      configuredPublicInputSchemaVersion
  ) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof public input schema version is unsupported.",
    );
  }

  const publicInputs = proof.publicInputs;
  if (
    publicInputs.proofSystemVersion !== CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION ||
    publicInputs.hashSuite !== CIVIC_PRODUCTION_HASH_SUITE
  ) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof public inputs use an unsupported proof or hash suite.",
    );
  }

  if (proof.publicInputsHash !== hashGroth16TallyPublicInputs(publicInputs)) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof public input hash does not match the public inputs.",
    );
  }

  const optionCount = normalizeOptionCount(publicInputs.optionCount);
  const expectedOptionIds = (params.expectedOptionIds ?? [])
    .map((optionId) => optionId.trim())
    .filter(Boolean);
  if (
    !optionCount ||
    expectedOptionIds.length !== optionCount ||
    publicInputs.optionResults.length !== optionCount
  ) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof option count does not match the registered poll options.",
    );
  }
  const optionIdsMatch = publicInputs.optionResults.every(
    (entry, index) => entry.optionId === expectedOptionIds[index],
  );
  if (!optionIdsMatch) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof option results are not ordered by the registered poll options.",
    );
  }

  const optionCountsHash = await hashGroth16TallyOptionCounts(
    publicInputs.optionResults,
  );
  if (publicInputs.optionResults.length > CIVIC_TALLY_MAX_OPTIONS) {
    return reject(
      "PROOF_INVALID",
      `Groth16 tally proof supports at most ${CIVIC_TALLY_MAX_OPTIONS} options.`,
    );
  }
  if (publicInputs.acceptedVoteCount > CIVIC_TALLY_MAX_VOTES) {
    return reject(
      "PROOF_INVALID",
      `Groth16 tally proof supports at most ${CIVIC_TALLY_MAX_VOTES} votes per batch.`,
    );
  }
  if (publicInputs.optionCountsHash !== optionCountsHash) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof option counts hash does not match the public counts.",
    );
  }

  if (publicInputs.pollId !== params.poll.id) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof poll id does not match the requested poll.",
    );
  }

  const pollPolicyHash = normalizeHex64(params.poll.poll_policy_hash);
  if (!pollPolicyHash || publicInputs.pollPolicyHash !== pollPolicyHash) {
    return reject(
      "POLL_POLICY_HASH_MISMATCH",
      "Groth16 tally proof poll policy hash does not match the registered poll policy.",
    );
  }

  const credentialSchemaHash = normalizeHex64(params.poll.credential_schema_hash);
  if (
    !credentialSchemaHash ||
    publicInputs.credentialSchemaHash !== credentialSchemaHash
  ) {
    return reject(
      "CREDENTIAL_SCHEMA_HASH_MISMATCH",
      "Groth16 tally proof credential schema hash does not match the registered poll schema.",
    );
  }

  const optionSetHash = normalizeHex64(params.poll.option_set_hash);
  if (!optionSetHash || publicInputs.optionSetHash !== optionSetHash) {
    return reject(
      "OPTION_SET_HASH_MISMATCH",
      "Groth16 tally proof option set hash does not match the registered poll option set.",
    );
  }

  if (
    publicInputs.nullifierRoot !== params.nullifierRoot ||
    publicInputs.voteCommitmentRoot !== params.voteCommitmentRoot ||
    publicInputs.encryptedVoteRoot !== params.encryptedVoteRoot ||
    publicInputs.acceptedVoteCount !== params.acceptedVoteCount
  ) {
    return reject(
      "ROOT_MISMATCH",
      "Groth16 tally proof roots or accepted count do not match the committed vote set.",
    );
  }

  const sum = publicInputs.optionResults.reduce(
    (total, entry) => total + Math.max(0, Math.trunc(entry.count)),
    0,
  );
  if (sum !== params.acceptedVoteCount) {
    return reject(
      "PROOF_INVALID",
      "Groth16 tally proof public counts do not sum to the accepted vote count.",
    );
  }

  const publicSignals = encodeGroth16TallyPublicSignals(publicInputs);
  const verifyProof = dependencies.verifyProof ?? defaultVerifyProof;
  const accepted = await verifyProof({
    proof: proof.proof,
    publicInputs,
    publicSignals,
    artifactManifest,
    artifactManifestPath: config.tallyArtifactManifestPath,
    artifactManifestHash,
    verifierKeyHash: configuredVerifierKeyHash,
  });

  if (!accepted) {
    return reject(
      "VERIFIER_REJECTED",
      "Groth16 tally proof was rejected by the verifier.",
    );
  }

  const tallyProofHash = hashGroth16TallyProofEnvelope(proof);
  const resultHash = sha256Hex(
    `${CIVIC_ZKP_DOMAIN}|groth16-tally-result|${canonicalizeJson({
      pollId: params.poll.id,
      nullifierRoot: params.nullifierRoot,
      voteCommitmentRoot: params.voteCommitmentRoot,
      encryptedVoteRoot: params.encryptedVoteRoot,
      acceptedVoteCount: params.acceptedVoteCount,
      optionCount,
      optionResults: publicInputs.optionResults,
      tallyProofHash,
      tallyPublicInputsHash: proof.publicInputsHash,
      tallyVerifierKeyHash: configuredVerifierKeyHash,
    })}`,
  );

  return {
    ok: true,
    auditMaterial: {
      resultHash,
      tallyProofHash,
      tallyPublicInputsHash: proof.publicInputsHash,
      tallyVerifierKeyHash: configuredVerifierKeyHash,
      tallyCircuitId: configuredCircuitId,
      nullifierRoot: params.nullifierRoot,
      voteCommitmentRoot: params.voteCommitmentRoot,
      encryptedVoteRoot: params.encryptedVoteRoot,
      acceptedCount: params.acceptedVoteCount,
      proofEnvelopeJson: proof,
    },
  };
};

export default {
  CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
  CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  GROTH16_TALLY_PUBLIC_SIGNAL_ORDER,
  encodeGroth16TallyPublicSignals,
  getGroth16TallyVerifierConfig,
  hashGroth16TallyOptionCounts,
  hashGroth16TallyProofEnvelope,
  hashGroth16TallyPublicInputs,
  isGroth16TallyVerifierConfigured,
  verifyGroth16TallyProofForPoll,
};
