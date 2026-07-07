import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "bun:test";

import type { PollRow } from "../types/db";
import {
  GROTH16_ARTIFACT_MANIFEST_VERSION,
  buildGroth16VerifierKeyRegistryRecord,
  hashGroth16ArtifactManifest,
  type Groth16ArtifactManifest,
} from "./groth16ArtifactManifestService";
import {
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
  CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
  CIVIC_PRODUCTION_PROOF_PROTOCOL,
  CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
  CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  getGroth16VerifierConfig,
  hashGroth16VotePublicInputs,
  isGroth16VoteVerifierConfigured,
  type Groth16VerifierConfig,
  type Groth16VoteProofEnvelopeDto,
  type Groth16VotePublicInputsDto,
  verifyGroth16VoteProofForPoll,
} from "./groth16ProofVerifierService";
import {
  encodeGroth16VotePublicSignals,
  verifyGroth16ProofWithSnarkjs,
} from "./groth16SnarkjsVerifierEngine";

const FIXED_TIME = "2026-07-07T12:00:00.000Z";
const POLL_POLICY_HASH = "1".repeat(64);
const CREDENTIAL_SCHEMA_HASH = "2".repeat(64);
const OPTION_SET_HASH = "3".repeat(64);
const CREDENTIAL_ROOT = "4".repeat(64);
const NULLIFIER = "5".repeat(64);
const VOTE_COMMITMENT = "6".repeat(64);
const ENCRYPTED_VOTE_HASH = "7".repeat(64);
const ENCRYPTED_VOTE_COMMITMENT = "c".repeat(64);
const VERIFIER_KEY_HASH = "8".repeat(64);
const TRUSTED_SETUP_TRANSCRIPT_HASH = "9".repeat(64);
const PROVING_KEY_HASH = "a".repeat(64);
const PROVER_ARTIFACT_HASH = "b".repeat(64);
const CIRCUIT_ID = "civicos-groth16-vote-circuit-v1";
const fixtureUrl = new URL("./__fixtures__/groth16-vote/", import.meta.url);
const fixtureManifestPath = new URL(
  "credential_commitment_vote.manifest.json",
  fixtureUrl,
);
const fixtureManifest = JSON.parse(
  readFileSync(fixtureManifestPath, "utf8"),
) as Groth16ArtifactManifest;
const fixtureManifestHash = readFileSync(
  new URL("credential_commitment_vote.manifest-hash.txt", fixtureUrl),
  "utf8",
).trim();
const fixtureEnvelope = JSON.parse(
  readFileSync(
    new URL("credential_commitment_vote.envelope.json", fixtureUrl),
    "utf8",
  ),
) as Groth16VoteProofEnvelopeDto;
const fixturePublicSignals = JSON.parse(
  readFileSync(
    new URL("credential_commitment_vote.public.json", fixtureUrl),
    "utf8",
  ),
) as string[];
const fixtureVerificationKey = JSON.parse(
  readFileSync(
    new URL("credential_commitment_vote.vkey.json", fixtureUrl),
    "utf8",
  ),
);

const createArtifactManifest = (
  overrides: Partial<Groth16ArtifactManifest> = {},
): Groth16ArtifactManifest => ({
  version: GROTH16_ARTIFACT_MANIFEST_VERSION,
  artifactKind: "vote",
  circuitId: CIRCUIT_ID,
  proofSystem: "groth16",
  protocol: "groth16",
  curve: "bn254",
  hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
  publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  trustedSetupTranscriptHash: TRUSTED_SETUP_TRANSCRIPT_HASH,
  verifierKeyHash: VERIFIER_KEY_HASH,
  provingKeyHash: PROVING_KEY_HASH,
  wasmOrNativeArtifactHash: PROVER_ARTIFACT_HASH,
  artifacts: [
    {
      role: "verification_key",
      path: "vote.vkey.json",
      sha256: VERIFIER_KEY_HASH,
      format: "snarkjs-vkey-json",
    },
    {
      role: "proving_key",
      path: "vote.zkey",
      sha256: PROVING_KEY_HASH,
      format: "zkey",
    },
    {
      role: "witness_wasm",
      path: "vote.wasm",
      sha256: PROVER_ARTIFACT_HASH,
      format: "wasm",
    },
  ],
  ...overrides,
});

const artifactManifest = createArtifactManifest();
const artifactManifestHash = hashGroth16ArtifactManifest(artifactManifest);
const verifierKeyRegistryRecord = buildGroth16VerifierKeyRegistryRecord(
  artifactManifest,
  artifactManifestHash,
);

const configuredVerifier: Groth16VerifierConfig = {
  voteVerifierEnabled: true,
  voteCircuitId: CIRCUIT_ID,
  voteVerifierKeyHash: VERIFIER_KEY_HASH,
  publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  trustedSetupTranscriptHash: TRUSTED_SETUP_TRANSCRIPT_HASH,
  voteArtifactManifestPath: "/zkp/vote.manifest.json",
  voteArtifactManifestHash: artifactManifestHash,
  voteArtifactManifest: artifactManifest,
  voteArtifactManifestStatus: "loaded",
  voteArtifactManifestError: null,
  voteVerifierKeyRegistryRecord: verifierKeyRegistryRecord,
};

const disabledVerifier: Groth16VerifierConfig = {
  ...configuredVerifier,
  voteVerifierEnabled: false,
};

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: null,
  title: "Production ZKP poll",
  description: null,
  status: "active",
  jurisdiction_type: "global",
  jurisdiction_country_code: null,
  jurisdiction_area_ids: [],
  jurisdiction_land_ids: [],
  requires_verified_identity: true,
  allowed_document_country_codes: [],
  allowed_home_area_ids: [],
  allowed_land_ids: [],
  minimum_age: null,
  starts_at: null,
  ends_at: null,
  poll_policy_json: null,
  poll_policy_hash: POLL_POLICY_HASH,
  credential_schema_json: null,
  credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
  vote_privacy_mode: "zk_secret_ballot_v1",
  option_set_hash: OPTION_SET_HASH,
  poll_encryption_key_id: "poll-key-1",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createProof = (
  overrides: Partial<Groth16VotePublicInputsDto> & {
    publicInputsHash?: string;
    verifierKeyHash?: string;
    circuitId?: string;
  } = {},
): Groth16VoteProofEnvelopeDto => {
  const publicInputs: Groth16VotePublicInputsDto = {
    version: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
    pollId: overrides.pollId ?? "poll-1",
    pollPolicyHash: overrides.pollPolicyHash ?? POLL_POLICY_HASH,
    credentialSchemaHash:
      overrides.credentialSchemaHash ?? CREDENTIAL_SCHEMA_HASH,
    optionSetHash: overrides.optionSetHash ?? OPTION_SET_HASH,
    credentialRoot: overrides.credentialRoot ?? CREDENTIAL_ROOT,
    nullifier: overrides.nullifier ?? NULLIFIER,
    voteCommitment: overrides.voteCommitment ?? VOTE_COMMITMENT,
    encryptedVoteHash: overrides.encryptedVoteHash ?? ENCRYPTED_VOTE_HASH,
    encryptedVoteCommitment:
      overrides.encryptedVoteCommitment ?? ENCRYPTED_VOTE_COMMITMENT,
    verificationMethodVersion:
      overrides.verificationMethodVersion ??
      "civicos-mobile-verification-v1",
    proofSystemVersion:
      overrides.proofSystemVersion ?? CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    hashSuite: overrides.hashSuite ?? CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: overrides.circuitId ?? CIRCUIT_ID,
    verifierKeyHash: overrides.verifierKeyHash ?? VERIFIER_KEY_HASH,
    publicInputSchemaVersion:
      overrides.publicInputSchemaVersion ??
      CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  };

  return {
    version: CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
    protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: overrides.circuitId ?? CIRCUIT_ID,
    verifierKeyHash: overrides.verifierKeyHash ?? VERIFIER_KEY_HASH,
    publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
    proof: {
      pi_a: ["1", "2", "1"],
      pi_b: [
        ["3", "4"],
        ["5", "6"],
        ["1", "0"],
      ],
      pi_c: ["7", "8", "1"],
    },
    publicInputs,
    publicInputsHash:
      overrides.publicInputsHash ?? hashGroth16VotePublicInputs(publicInputs),
  };
};

describe("groth16ProofVerifierService", () => {
  it("reports verifier configuration readiness", () => {
    expect(isGroth16VoteVerifierConfigured(disabledVerifier)).toBe(false);
    expect(isGroth16VoteVerifierConfigured(configuredVerifier)).toBe(true);
    expect(
      isGroth16VoteVerifierConfigured({
        ...configuredVerifier,
        voteVerifierKeyHash: null,
      }),
    ).toBe(false);
    expect(
      isGroth16VoteVerifierConfigured({
        ...configuredVerifier,
        voteArtifactManifestStatus: "not_configured",
        voteArtifactManifest: null,
        voteVerifierKeyRegistryRecord: null,
      }),
    ).toBe(false);
  });

  it("keeps env-loaded manifests unconfigured without a pinned manifest hash", () => {
    const oldPath = process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH;
    const oldHash = process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH;
    const oldEnabled = process.env.ZKP_GROTH16_VOTE_VERIFIER_ENABLED;
    const dir = mkdtempSync(join(tmpdir(), "civicos-groth16-config-"));
    const manifestPath = join(dir, "vote.manifest.json");
    writeFileSync(manifestPath, JSON.stringify(artifactManifest, null, 2));

    try {
      process.env.ZKP_GROTH16_VOTE_VERIFIER_ENABLED = "true";
      process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH = manifestPath;
      delete process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH;

      const config = getGroth16VerifierConfig();
      expect(config.voteArtifactManifestStatus).toBe("invalid");
      expect(config.voteArtifactManifestError).toContain("must be pinned");
      expect(isGroth16VoteVerifierConfigured(config)).toBe(false);
    } finally {
      if (oldPath === undefined) {
        delete process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH;
      } else {
        process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH = oldPath;
      }
      if (oldHash === undefined) {
        delete process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH;
      } else {
        process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH = oldHash;
      }
      if (oldEnabled === undefined) {
        delete process.env.ZKP_GROTH16_VOTE_VERIFIER_ENABLED;
      } else {
        process.env.ZKP_GROTH16_VOTE_VERIFIER_ENABLED = oldEnabled;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fails closed when production ZKP poll verification is disabled", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
        expectedVoteCommitment: VOTE_COMMITMENT,
      },
      {
        config: disabledVerifier,
        verifyProof: () => true,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("VERIFIER_DISABLED");
    }
  });

  it("fails closed when the default verifier cannot load the pinned key", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
      },
      {
        config: configuredVerifier,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("VERIFIER_REJECTED");
    }
  });

  it("fails closed when loose verifier fields are set without a pinned artifact manifest", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
      },
      {
        config: {
          ...configuredVerifier,
          voteArtifactManifestPath: null,
          voteArtifactManifestHash: null,
          voteArtifactManifest: null,
          voteArtifactManifestStatus: "not_configured",
          voteArtifactManifestError: null,
          voteVerifierKeyRegistryRecord: null,
        },
        verifyProof: () => true,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("VERIFIER_UNCONFIGURED");
    }
  });

  it("accepts a configured verifier engine result and returns anonymous audit material", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
        expectedVoteCommitment: VOTE_COMMITMENT,
      },
      {
        config: configuredVerifier,
        verifyProof: async (input) => {
          expect(input.circuitId).toBe(CIRCUIT_ID);
          expect(input.verifierKeyHash).toBe(VERIFIER_KEY_HASH);
          expect(input.trustedSetupTranscriptHash).toBe(
            TRUSTED_SETUP_TRANSCRIPT_HASH,
          );
          expect(input.artifactManifest).toBe(artifactManifest);
          expect(input.artifactManifestHash).toBe(artifactManifestHash);
          expect(input.verifierKeyRegistryRecord).toEqual(
            verifierKeyRegistryRecord,
          );
          return true;
        },
      },
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.auditMaterial).toMatchObject({
        nullifier: NULLIFIER,
        voteCommitment: VOTE_COMMITMENT,
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
        encryptedVoteCommitment: ENCRYPTED_VOTE_COMMITMENT,
        proofSystemVersion: "civicos-zk-proof-v1",
        proofVerificationStatus: "verified",
        verifierKeyHash: VERIFIER_KEY_HASH,
        circuitId: CIRCUIT_ID,
      });
      expect(result.auditMaterial?.proofHash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.auditMaterial?.proofEnvelopeHash).toBe(
        result.auditMaterial?.proofHash,
      );
    }
  });

  it("verifies the local CredentialCommitmentVote proof fixture with snarkjs", async () => {
    expect(encodeGroth16VotePublicSignals(fixtureEnvelope.publicInputs)).toEqual(
      fixturePublicSignals,
    );

    await expect(
      verifyGroth16ProofWithSnarkjs({
        verificationKey: fixtureVerificationKey,
        proof: fixtureEnvelope.proof,
        publicSignals: fixturePublicSignals,
      }),
    ).resolves.toBe(true);

    await expect(
      verifyGroth16ProofWithSnarkjs({
        verificationKey: fixtureVerificationKey,
        proof: fixtureEnvelope.proof,
        publicSignals: [
          (BigInt(fixturePublicSignals[0]) + 1n).toString(10),
          ...fixturePublicSignals.slice(1),
        ],
      }),
    ).resolves.toBe(false);
  });

  it("accepts the local CredentialCommitmentVote fixture through the default verifier engine", async () => {
    const registryRecord = buildGroth16VerifierKeyRegistryRecord(
      fixtureManifest,
      fixtureManifestHash,
    );
    const fixtureConfig: Groth16VerifierConfig = {
      voteVerifierEnabled: true,
      voteCircuitId: fixtureManifest.circuitId,
      voteVerifierKeyHash: fixtureManifest.verifierKeyHash,
      publicInputSchemaVersion: fixtureManifest.publicInputSchemaVersion,
      trustedSetupTranscriptHash: fixtureManifest.trustedSetupTranscriptHash,
      voteArtifactManifestPath: fixtureManifestPath.pathname,
      voteArtifactManifestHash: fixtureManifestHash,
      voteArtifactManifest: fixtureManifest,
      voteArtifactManifestStatus: "loaded",
      voteArtifactManifestError: null,
      voteVerifierKeyRegistryRecord: registryRecord,
    };

    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll({
          id: fixtureEnvelope.publicInputs.pollId,
          poll_policy_hash: fixtureEnvelope.publicInputs.pollPolicyHash,
          credential_schema_hash:
            fixtureEnvelope.publicInputs.credentialSchemaHash,
          option_set_hash: fixtureEnvelope.publicInputs.optionSetHash,
        }),
        proof: fixtureEnvelope,
        encryptedVoteHash: fixtureEnvelope.publicInputs.encryptedVoteHash,
        expectedVoteCommitment: fixtureEnvelope.publicInputs.voteCommitment,
      },
      { config: fixtureConfig },
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.auditMaterial).toMatchObject({
        nullifier: fixtureEnvelope.publicInputs.nullifier,
        voteCommitment: fixtureEnvelope.publicInputs.voteCommitment,
        encryptedVoteHash: fixtureEnvelope.publicInputs.encryptedVoteHash,
        encryptedVoteCommitment:
          fixtureEnvelope.publicInputs.encryptedVoteCommitment,
        proofVerificationStatus: "verified",
        verifierKeyHash: fixtureManifest.verifierKeyHash,
        circuitId: fixtureManifest.circuitId,
      });
    }
  });

  it("rejects public input hash mismatch before calling the verifier engine", async () => {
    let verifierCalled = false;
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof({ publicInputsHash: "a".repeat(64) }),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
      },
      {
        config: configuredVerifier,
        verifyProof: () => {
          verifierCalled = true;
          return true;
        },
      },
    );

    expect(result.ok).toBe(false);
    expect(verifierCalled).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("PROOF_INVALID");
    }
  });

  it("rejects mixed pre-prover status in a production envelope", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: {
          ...createProof(),
          status: "not_generated",
        },
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
      },
      {
        config: configuredVerifier,
        verifyProof: () => true,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("PROOF_INVALID");
    }
  });

  it("rejects pre-prover proof-system values in production public inputs", async () => {
    const proof = createProof({
      proofSystemVersion: "civicos-zk-proof-v1-preprover",
    });

    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof,
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
      },
      {
        config: configuredVerifier,
        verifyProof: () => true,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("PROOF_INVALID");
    }
  });

  it("rejects verifier rejection", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
      },
      {
        config: configuredVerifier,
        verifyProof: () => false,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("VERIFIER_REJECTED");
    }
  });

  it("keeps non-production polls out of the Groth16 verifier path", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll({ vote_privacy_mode: "zk_preprover_audit" }),
        proof: null,
      },
      {
        config: configuredVerifier,
      },
    );

    expect(result).toEqual({ ok: true, auditMaterial: null });
  });
});
