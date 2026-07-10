import { describe, expect, it } from "bun:test";

import {
  getProofSystemPolicy,
  proofSystemPolicyService,
} from "./proofSystemPolicyService";

const withClearedGroth16VoteEnv = <T>(run: () => T): T => {
  const keys = [
    "ZKP_GROTH16_VOTE_VERIFIER_ENABLED",
    "ZKP_GROTH16_VOTE_CIRCUIT_ID",
    "ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH",
    "ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION",
    "ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH",
    "ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION",
    "ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH",
    "ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH",
    "ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH",
  ] as const;
  const previous = new Map<string, string | undefined>(
    keys.map((key) => [key, process.env[key]]),
  );

  for (const key of keys) {
    delete process.env[key];
  }

  try {
    return run();
  } finally {
    for (const key of keys) {
      const value = previous.get(key);
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
};

describe("proofSystemPolicyService", () => {
  it("selects the Phase 11 v1 off-chain verifier policy", () => {
    const policy = getProofSystemPolicy();

    expect(policy).toMatchObject({
      version: "civicos-proof-system-policy-v1",
      phase: 11,
      selectedTrack: "v1",
      proofSystemVersion: "civicos-zk-proof-v1-preprover",
      proofVerificationMode: "off_chain_preprover",
      proofVerificationStatus: "preprover_accepted",
      onChainZkVerifierEnabled: false,
      solanaAnchoring: "audit_roots_only",
      storesProofHash: true,
      storesPublicInputs: true,
      storesPrivateWitness: false,
    });
  });

  it("keeps Solana limited to audit artifacts for v1", () => {
    const policy = withClearedGroth16VoteEnv(() =>
      proofSystemPolicyService.getPolicy(),
    );

    expect(proofSystemPolicyService.isOnChainZkVerifierEnabled()).toBe(false);
    expect(policy.solanaArtifacts).toEqual([
      "nullifier_root",
      "vote_commitment_root",
      "encrypted_vote_root",
      "final_result_hash",
      "tally_proof_hash",
      "tally_public_inputs_hash",
    ]);
    expect(policy.offChainArtifacts).toEqual([
      "proof_hash",
      "public_inputs",
      "proof_envelope",
      "groth16_proof",
      "encrypted_vote",
      "tally_proof",
    ]);
    expect(policy.productionTarget).toMatchObject({
      enabled: false,
      verifierConfigured: false,
      proofSystemVersion: "civicos-zk-proof-v1",
      proofVerificationMode: "off_chain_groth16",
      proofVerificationStatus: "verified",
      hashSuite: "poseidon-bn254-v1",
      anonymousVoteTable: "poll_zk_votes",
      tallyProofRequired: true,
      onChainZkVerifierEnabled: false,
      artifactManifestConfigured: true,
    });
    expect(policy.productionTarget.verifierKeyRegistryRecord).toMatchObject({
      artifactKind: "vote",
      circuitId: "civicos-groth16-vote-circuit-v1",
      publicInputSchemaVersion: "civicos-groth16-vote-public-inputs-v1",
    });
  });
});
