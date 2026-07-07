import { createHash } from "node:crypto";

import type { PollRow } from "../types/db";
import type { JsonValue } from "../types/json";
import {
  loadGroth16ArtifactManifestFile,
  validateGroth16ArtifactManifestConstraints,
  type Groth16ArtifactManifest,
  type Groth16VerifierKeyRegistryRecord,
} from "./groth16ArtifactManifestService";
import { verifyGroth16VoteProofWithSnarkjs } from "./groth16SnarkjsVerifierEngine";
import { canonicalizeJson } from "./pollPolicyService";

export const CIVIC_PRODUCTION_VOTE_PRIVACY_MODE =
  "zk_secret_ballot_v1" as const;
export const CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION =
  "civicos-groth16-vote-proof-envelope-v1" as const;
export const CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION =
  "civicos-zk-proof-v1" as const;
export const CIVIC_PRODUCTION_PROOF_PROTOCOL = "groth16" as const;
export const CIVIC_PRODUCTION_HASH_SUITE = "poseidon-bn254-v1" as const;
export const CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION =
  "civicos-groth16-vote-public-inputs-v1" as const;
export const CIVIC_PRODUCTION_PROOF_GENERATED_STATUS = "generated" as const;
export const CIVIC_PRODUCTION_PROOF_VERIFICATION_MODE =
  "off_chain_groth16" as const;
export const CIVIC_PRODUCTION_PROOF_VERIFICATION_STATUS = "verified" as const;
export const CIVIC_PRODUCTION_ENCRYPTED_VOTE_VERSION =
  "civicos-encrypted-vote-v1" as const;

const CIVIC_ZKP_DOMAIN = "org.civicos.zkp" as const;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

export type Groth16VotePublicInputsDto = {
  version: string;
  pollId: string;
  pollPolicyHash: string;
  credentialSchemaHash: string;
  optionSetHash: string;
  credentialRoot: string;
  nullifier: string;
  voteCommitment: string;
  encryptedVoteHash: string;
  encryptedVoteCommitment: string;
  verificationMethodVersion: string;
  proofSystemVersion: string;
  hashSuite: string;
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
};

export type Groth16VoteProofEnvelopeDto = {
  version: string;
  protocol: string;
  proofSystemVersion: string;
  status: string;
  hashSuite: string;
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
  proof: JsonValue;
  publicInputs: Groth16VotePublicInputsDto;
  publicInputsHash: string;
};

export type Groth16VerifierConfig = {
  voteVerifierEnabled: boolean;
  voteCircuitId: string | null;
  voteVerifierKeyHash: string | null;
  publicInputSchemaVersion: string | null;
  trustedSetupTranscriptHash: string | null;
  voteArtifactManifestPath: string | null;
  voteArtifactManifestHash: string | null;
  voteArtifactManifest: Groth16ArtifactManifest | null;
  voteArtifactManifestStatus:
    | "not_configured"
    | "loaded"
    | "invalid"
    | "hash_mismatch"
    | "kind_mismatch"
    | "config_mismatch";
  voteArtifactManifestError: string | null;
  voteVerifierKeyRegistryRecord: Groth16VerifierKeyRegistryRecord | null;
};

export type Groth16VoteVerifierEngine = (input: {
  proof: JsonValue;
  publicInputs: Groth16VotePublicInputsDto;
  circuitId: string;
  verifierKeyHash: string;
  trustedSetupTranscriptHash: string;
  artifactManifest: Groth16ArtifactManifest;
  artifactManifestPath: string | null;
  artifactManifestHash: string;
  verifierKeyRegistryRecord: Groth16VerifierKeyRegistryRecord;
}) => boolean | Promise<boolean>;

export type VerifiedGroth16VoteProofAuditMaterial = {
  nullifier: string;
  voteCommitment: string;
  encryptedVoteHash: string;
  encryptedVoteCommitment: string;
  proofHash: string;
  proofSystemVersion: typeof CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION;
  verificationMethodVersion: string;
  proofVerificationStatus: typeof CIVIC_PRODUCTION_PROOF_VERIFICATION_STATUS;
  proofPublicInputsJson: Groth16VotePublicInputsDto;
  proofEnvelopeHash: string;
  verifierKeyHash: string;
  circuitId: string;
};

export type Groth16VoteProofVerificationResult =
  | {
      ok: true;
      auditMaterial: VerifiedGroth16VoteProofAuditMaterial | null;
    }
  | {
      ok: false;
      reason:
        | "PROOF_REQUIRED"
        | "PROOF_INVALID"
        | "POLL_POLICY_HASH_MISMATCH"
        | "CREDENTIAL_SCHEMA_HASH_MISMATCH"
        | "OPTION_SET_HASH_MISMATCH"
        | "CIRCUIT_ID_MISMATCH"
        | "VERIFIER_KEY_MISMATCH"
        | "VERIFIER_DISABLED"
        | "VERIFIER_UNCONFIGURED"
        | "VERIFIER_UNAVAILABLE"
        | "VERIFIER_REJECTED";
      message: string;
    };

export type Groth16ProofVerifierDependencies = {
  config?: Groth16VerifierConfig;
  verifyProof?: Groth16VoteVerifierEngine | null;
};

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const normalizeHex64 = (value: string | null | undefined): string | null => {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return HEX_64_PATTERN.test(normalized) ? normalized : null;
};

const normalizeOptionalString = (value: string | undefined): string | null => {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized.length > 0 ? normalized : null;
};

const toBoolean = (value: string | undefined): boolean => {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return normalized === "1" || normalized === "true" || normalized === "yes";
};

const missingArtifactManifestConfig = (
  values: Pick<
    Groth16VerifierConfig,
    | "voteVerifierEnabled"
    | "voteCircuitId"
    | "voteVerifierKeyHash"
    | "publicInputSchemaVersion"
    | "trustedSetupTranscriptHash"
  >,
): Groth16VerifierConfig => ({
  ...values,
  voteArtifactManifestPath: null,
  voteArtifactManifestHash: null,
  voteArtifactManifest: null,
  voteArtifactManifestStatus: "not_configured",
  voteArtifactManifestError: null,
  voteVerifierKeyRegistryRecord: null,
});

const loadVoteArtifactManifestFromEnv = (values: {
  voteVerifierEnabled: boolean;
  voteCircuitId: string | null;
  voteVerifierKeyHash: string | null;
  publicInputSchemaVersion: string | null;
  trustedSetupTranscriptHash: string | null;
}): Groth16VerifierConfig => {
  const voteArtifactManifestPath = normalizeOptionalString(
    process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH,
  );
  const rawVoteArtifactManifestHash = normalizeOptionalString(
    process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH,
  );
  const voteArtifactManifestHash = normalizeHex64(
    process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH,
  );

  if (!voteArtifactManifestPath) {
    return missingArtifactManifestConfig(values);
  }

  if (!rawVoteArtifactManifestHash || !voteArtifactManifestHash) {
    return {
      ...values,
      voteArtifactManifestPath,
      voteArtifactManifestHash,
      voteArtifactManifest: null,
      voteArtifactManifestStatus: "invalid",
      voteArtifactManifestError:
        "Groth16 vote artifact manifest hash must be pinned.",
      voteVerifierKeyRegistryRecord: null,
    };
  }

  const loaded = loadGroth16ArtifactManifestFile({
    manifestPath: voteArtifactManifestPath,
    expectedManifestHash: voteArtifactManifestHash,
    expectedArtifactKind: "vote",
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
      voteArtifactManifestPath,
      voteArtifactManifestHash,
      voteArtifactManifest: null,
      voteArtifactManifestStatus: status,
      voteArtifactManifestError: loaded.message,
      voteVerifierKeyRegistryRecord: null,
    };
  }

  const voteCircuitId = values.voteCircuitId ?? loaded.manifest.circuitId;
  const voteVerifierKeyHash =
    values.voteVerifierKeyHash ?? loaded.manifest.verifierKeyHash;
  const publicInputSchemaVersion =
    values.publicInputSchemaVersion ??
    loaded.manifest.publicInputSchemaVersion;
  const trustedSetupTranscriptHash =
    values.trustedSetupTranscriptHash ??
    loaded.manifest.trustedSetupTranscriptHash;

  const constraints = validateGroth16ArtifactManifestConstraints(
    loaded.manifest,
    {
      artifactKind: "vote",
      circuitId: voteCircuitId,
      verifierKeyHash: voteVerifierKeyHash,
      publicInputSchemaVersion,
      trustedSetupTranscriptHash,
      hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
      protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
    },
  );

  if (!constraints.ok) {
    return {
      ...values,
      voteArtifactManifestPath,
      voteArtifactManifestHash,
      voteArtifactManifest: loaded.manifest,
      voteArtifactManifestStatus: "config_mismatch",
      voteArtifactManifestError: constraints.message,
      voteVerifierKeyRegistryRecord: null,
    };
  }

  return {
    voteVerifierEnabled: values.voteVerifierEnabled,
    voteCircuitId,
    voteVerifierKeyHash,
    publicInputSchemaVersion,
    trustedSetupTranscriptHash,
    voteArtifactManifestPath,
    voteArtifactManifestHash: loaded.manifestHash,
    voteArtifactManifest: loaded.manifest,
    voteArtifactManifestStatus: "loaded",
    voteArtifactManifestError: null,
    voteVerifierKeyRegistryRecord: loaded.registryRecord,
  };
};

export const hashGroth16VotePublicInputs = (
  publicInputs: Groth16VotePublicInputsDto,
): string =>
  sha256Hex(
    `${CIVIC_ZKP_DOMAIN}|groth16-vote-public-inputs|${canonicalizeJson(publicInputs)}`,
  );

export const hashGroth16VoteProofEnvelope = (
  proof: Groth16VoteProofEnvelopeDto,
): string =>
  sha256Hex(
    `${CIVIC_ZKP_DOMAIN}|groth16-vote-proof-envelope|${canonicalizeJson(proof)}`,
  );

export const hashEncryptedVotePayload = (encryptedVote: JsonValue): string =>
  sha256Hex(
    `${CIVIC_ZKP_DOMAIN}|encrypted-vote|${canonicalizeJson(encryptedVote)}`,
  );

export const getGroth16VerifierConfig = (): Groth16VerifierConfig =>
  loadVoteArtifactManifestFromEnv({
    voteVerifierEnabled: toBoolean(
      process.env.ZKP_GROTH16_VOTE_VERIFIER_ENABLED,
    ),
    voteCircuitId: normalizeOptionalString(
      process.env.ZKP_GROTH16_VOTE_CIRCUIT_ID,
    ),
    voteVerifierKeyHash: normalizeHex64(
      process.env.ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH,
    ),
    publicInputSchemaVersion: normalizeOptionalString(
      process.env.ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION,
    ) ?? normalizeOptionalString(process.env.ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION),
    trustedSetupTranscriptHash: normalizeHex64(
      process.env.ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH,
    ) ?? normalizeHex64(process.env.ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH),
  });

export const isGroth16VoteVerifierConfigured = (
  config: Groth16VerifierConfig = getGroth16VerifierConfig(),
): boolean =>
  Boolean(
    config.voteVerifierEnabled &&
      config.voteCircuitId &&
      config.voteVerifierKeyHash &&
      config.publicInputSchemaVersion &&
      config.trustedSetupTranscriptHash &&
      config.voteArtifactManifestStatus === "loaded" &&
      config.voteArtifactManifest &&
      config.voteVerifierKeyRegistryRecord,
  );

const hasProductionZkpPrivacyMode = (
  poll: Pick<PollRow, "vote_privacy_mode">,
): boolean => poll.vote_privacy_mode === CIVIC_PRODUCTION_VOTE_PRIVACY_MODE;

const reject = (
  reason: Extract<Groth16VoteProofVerificationResult, { ok: false }>["reason"],
  message: string,
): Groth16VoteProofVerificationResult => ({
  ok: false,
  reason,
  message,
});

export const verifyGroth16VoteProofForPoll = async (
  params: {
    poll: PollRow;
    proof?: Groth16VoteProofEnvelopeDto | null;
    encryptedVoteHash?: string | null;
    expectedVoteCommitment?: string | null;
  },
  dependencies: Groth16ProofVerifierDependencies = {},
): Promise<Groth16VoteProofVerificationResult> => {
  if (!hasProductionZkpPrivacyMode(params.poll)) {
    return { ok: true, auditMaterial: null };
  }

  if (!params.proof) {
    return reject("PROOF_REQUIRED", "This poll requires a Groth16 vote proof.");
  }

  const config = dependencies.config ?? getGroth16VerifierConfig();
  if (!config.voteVerifierEnabled) {
    return reject(
      "VERIFIER_DISABLED",
      "Groth16 vote proof verification is disabled for this backend.",
    );
  }

  if (!isGroth16VoteVerifierConfigured(config)) {
    return reject(
      "VERIFIER_UNCONFIGURED",
      "Groth16 vote proof verification is enabled but verifier artifacts are not fully configured.",
    );
  }

  const configuredCircuitId = config.voteCircuitId || "";
  const configuredVerifierKeyHash = config.voteVerifierKeyHash || "";
  const configuredPublicInputSchemaVersion =
    config.publicInputSchemaVersion || "";
  const configuredTrustedSetupTranscriptHash =
    config.trustedSetupTranscriptHash || "";
  const artifactManifest = config.voteArtifactManifest;
  const verifierKeyRegistryRecord = config.voteVerifierKeyRegistryRecord;
  const artifactManifestHash =
    verifierKeyRegistryRecord?.artifactManifestHash || "";

  if (!artifactManifest || !verifierKeyRegistryRecord || !artifactManifestHash) {
    return reject(
      "VERIFIER_UNCONFIGURED",
      "Groth16 vote proof verification is enabled but the pinned artifact manifest is unavailable.",
    );
  }

  const verifyProof =
    dependencies.verifyProof ?? verifyGroth16VoteProofWithSnarkjs;

  const proof = params.proof;
  if (
    proof.version !== CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION ||
    proof.protocol !== CIVIC_PRODUCTION_PROOF_PROTOCOL ||
    proof.proofSystemVersion !== CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION ||
    proof.status !== CIVIC_PRODUCTION_PROOF_GENERATED_STATUS ||
    proof.hashSuite !== CIVIC_PRODUCTION_HASH_SUITE
  ) {
    return reject(
      "PROOF_INVALID",
      "Groth16 vote proof envelope uses an unsupported version.",
    );
  }

  if (
    proof.circuitId !== configuredCircuitId ||
    proof.publicInputs.circuitId !== configuredCircuitId
  ) {
    return reject(
      "CIRCUIT_ID_MISMATCH",
      "Groth16 vote proof circuit id does not match the configured circuit.",
    );
  }

  if (
    proof.verifierKeyHash !== configuredVerifierKeyHash ||
    proof.publicInputs.verifierKeyHash !== configuredVerifierKeyHash
  ) {
    return reject(
      "VERIFIER_KEY_MISMATCH",
      "Groth16 vote proof verifier key hash does not match the configured verifier key.",
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
      "Groth16 vote proof public input schema version is unsupported.",
    );
  }

  const publicInputs = proof.publicInputs;
  if (
    publicInputs.proofSystemVersion !== CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION ||
    publicInputs.hashSuite !== CIVIC_PRODUCTION_HASH_SUITE
  ) {
    return reject(
      "PROOF_INVALID",
      "Groth16 vote proof public inputs use an unsupported proof or hash suite.",
    );
  }

  if (proof.publicInputsHash !== hashGroth16VotePublicInputs(publicInputs)) {
    return reject(
      "PROOF_INVALID",
      "Groth16 vote proof public input hash does not match the public inputs.",
    );
  }

  if (publicInputs.pollId !== params.poll.id) {
    return reject(
      "PROOF_INVALID",
      "Groth16 vote proof poll id does not match the requested poll.",
    );
  }

  const pollPolicyHash = normalizeHex64(params.poll.poll_policy_hash);
  if (!pollPolicyHash || publicInputs.pollPolicyHash !== pollPolicyHash) {
    return reject(
      "POLL_POLICY_HASH_MISMATCH",
      "Groth16 vote proof poll policy hash does not match the registered poll policy.",
    );
  }

  const credentialSchemaHash = normalizeHex64(params.poll.credential_schema_hash);
  if (
    !credentialSchemaHash ||
    publicInputs.credentialSchemaHash !== credentialSchemaHash
  ) {
    return reject(
      "CREDENTIAL_SCHEMA_HASH_MISMATCH",
      "Groth16 vote proof credential schema hash does not match the registered poll schema.",
    );
  }

  const optionSetHash = normalizeHex64(params.poll.option_set_hash);
  if (!optionSetHash || publicInputs.optionSetHash !== optionSetHash) {
    return reject(
      "OPTION_SET_HASH_MISMATCH",
      "Groth16 vote proof option set hash does not match the registered poll option set.",
    );
  }

  const nullifier = normalizeHex64(publicInputs.nullifier);
  const voteCommitment = normalizeHex64(publicInputs.voteCommitment);
  const encryptedVoteHash = normalizeHex64(publicInputs.encryptedVoteHash);
  const encryptedVoteCommitment = normalizeHex64(
    publicInputs.encryptedVoteCommitment,
  );
  const expectedEncryptedVoteHash = normalizeHex64(params.encryptedVoteHash);
  const expectedVoteCommitment = normalizeHex64(params.expectedVoteCommitment);
  const credentialRoot = normalizeHex64(publicInputs.credentialRoot);

  if (
    !nullifier ||
    !voteCommitment ||
    !encryptedVoteHash ||
    !encryptedVoteCommitment ||
    !credentialRoot
  ) {
    return reject(
      "PROOF_INVALID",
      "Groth16 vote proof contains malformed 32-byte public inputs.",
    );
  }

  if (
    expectedEncryptedVoteHash &&
    expectedEncryptedVoteHash !== encryptedVoteHash
  ) {
    return reject(
      "PROOF_INVALID",
      "Groth16 vote proof encrypted vote hash does not match the submitted ciphertext.",
    );
  }

  if (expectedVoteCommitment && expectedVoteCommitment !== voteCommitment) {
    return reject(
      "PROOF_INVALID",
      "Groth16 vote proof vote commitment does not match the submitted commitment.",
    );
  }

  let verifierAccepted = false;
  try {
    verifierAccepted = await verifyProof({
      proof: proof.proof,
      publicInputs,
      circuitId: configuredCircuitId,
      verifierKeyHash: configuredVerifierKeyHash,
      trustedSetupTranscriptHash: configuredTrustedSetupTranscriptHash,
      artifactManifest,
      artifactManifestPath: config.voteArtifactManifestPath,
      artifactManifestHash,
      verifierKeyRegistryRecord,
    });
  } catch {
    verifierAccepted = false;
  }

  if (!verifierAccepted) {
    return reject(
      "VERIFIER_REJECTED",
      "Groth16 vote proof was rejected by the verifier.",
    );
  }

  const proofHash = hashGroth16VoteProofEnvelope(proof);

  return {
    ok: true,
    auditMaterial: {
      nullifier,
      voteCommitment,
      encryptedVoteHash,
      encryptedVoteCommitment,
      proofHash,
      proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
      verificationMethodVersion: publicInputs.verificationMethodVersion,
      proofVerificationStatus: CIVIC_PRODUCTION_PROOF_VERIFICATION_STATUS,
      proofPublicInputsJson: publicInputs,
      proofEnvelopeHash: proofHash,
      verifierKeyHash: configuredVerifierKeyHash,
      circuitId: configuredCircuitId,
    },
  };
};

export default {
  getGroth16VerifierConfig,
  hashEncryptedVotePayload,
  hashGroth16VoteProofEnvelope,
  hashGroth16VotePublicInputs,
  isGroth16VoteVerifierConfigured,
  verifyGroth16VoteProofForPoll,
};
