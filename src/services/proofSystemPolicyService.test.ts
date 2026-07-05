import { describe, expect, it } from "bun:test";

import {
  getProofSystemPolicy,
  proofSystemPolicyService,
} from "./proofSystemPolicyService";

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
    const policy = proofSystemPolicyService.getPolicy();

    expect(proofSystemPolicyService.isOnChainZkVerifierEnabled()).toBe(false);
    expect(policy.solanaArtifacts).toEqual([
      "nullifier_root",
      "vote_commitment_root",
      "final_result_hash",
      "tally_proof_hash",
    ]);
    expect(policy.offChainArtifacts).toEqual([
      "proof_hash",
      "public_inputs",
      "proof_envelope",
    ]);
  });
});
