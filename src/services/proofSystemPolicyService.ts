import type { ProofSystemPolicyDto } from "../types/contracts";
import {
  CIVIC_PROOF_SYSTEM_VERSION,
  CIVIC_VOTE_PROOF_VERIFICATION_STATUS,
} from "./voteProofVerifierService";

export const CIVIC_PROOF_SYSTEM_POLICY_VERSION =
  "civicos-proof-system-policy-v1" as const;
export const CIVIC_PROOF_SYSTEM_TRACK = "v1" as const;
export const CIVIC_PROOF_VERIFICATION_MODE = "off_chain_preprover" as const;
export const CIVIC_SOLANA_ANCHORING_SCOPE = "audit_roots_only" as const;
export const CIVIC_ON_CHAIN_ZK_VERIFIER_ENABLED = false as const;

export const getProofSystemPolicy = (): ProofSystemPolicyDto => ({
  version: CIVIC_PROOF_SYSTEM_POLICY_VERSION,
  phase: 11,
  selectedTrack: CIVIC_PROOF_SYSTEM_TRACK,
  proofSystemVersion: CIVIC_PROOF_SYSTEM_VERSION,
  proofVerificationMode: CIVIC_PROOF_VERIFICATION_MODE,
  proofVerificationStatus: CIVIC_VOTE_PROOF_VERIFICATION_STATUS,
  onChainZkVerifierEnabled: CIVIC_ON_CHAIN_ZK_VERIFIER_ENABLED,
  solanaAnchoring: CIVIC_SOLANA_ANCHORING_SCOPE,
  storesProofHash: true,
  storesPublicInputs: true,
  storesPrivateWitness: false,
  solanaArtifacts: [
    "nullifier_root",
    "vote_commitment_root",
    "final_result_hash",
    "tally_proof_hash",
  ],
  offChainArtifacts: ["proof_hash", "public_inputs", "proof_envelope"],
  notes: [
    "CivicOS v1 keeps votes off-chain until result publication.",
    "The backend accepts pre-prover proof envelopes and records proof hashes plus public inputs for audit.",
    "The Solana audit program anchors roots and final hashes only; it does not verify ZK proofs on-chain.",
  ],
});

export const proofSystemPolicyService = {
  getPolicy: getProofSystemPolicy,
  isOnChainZkVerifierEnabled: () => CIVIC_ON_CHAIN_ZK_VERIFIER_ENABLED,
};

export default proofSystemPolicyService;
