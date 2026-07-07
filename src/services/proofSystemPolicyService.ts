import type { ProofSystemPolicyDto } from "../types/contracts";
import {
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
  CIVIC_PRODUCTION_PROOF_VERIFICATION_MODE,
  CIVIC_PRODUCTION_PROOF_VERIFICATION_STATUS,
  getGroth16VerifierConfig,
  isGroth16VoteVerifierConfigured,
} from "./groth16ProofVerifierService";
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

export const getProofSystemPolicy = (): ProofSystemPolicyDto => {
  const groth16Config = getGroth16VerifierConfig();
  const verifierConfigured = isGroth16VoteVerifierConfigured(groth16Config);

  return {
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
      "encrypted_vote_root",
      "final_result_hash",
      "tally_proof_hash",
      "tally_public_inputs_hash",
    ],
    offChainArtifacts: [
      "proof_hash",
      "public_inputs",
      "proof_envelope",
      "groth16_proof",
      "encrypted_vote",
      "tally_proof",
    ],
    productionTarget: {
      enabled: verifierConfigured,
      verifierConfigured,
      proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
      proofVerificationMode: CIVIC_PRODUCTION_PROOF_VERIFICATION_MODE,
      proofVerificationStatus: CIVIC_PRODUCTION_PROOF_VERIFICATION_STATUS,
      hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
      anonymousVoteTable: "poll_zk_votes",
      tallyProofRequired: true,
      onChainZkVerifierEnabled: CIVIC_ON_CHAIN_ZK_VERIFIER_ENABLED,
      artifactManifestConfigured:
        groth16Config.voteArtifactManifestStatus === "loaded",
      verifierKeyRegistryRecord: groth16Config.voteVerifierKeyRegistryRecord,
    },
    notes: [
      "CivicOS v1 keeps votes off-chain until result publication.",
      "The transition path accepts pre-prover proof envelopes and records proof hashes plus public inputs for audit.",
      "Production v1 requires Groth16 vote proofs, encrypted vote payloads, anonymous poll_zk_votes storage, and a public Groth16 tally proof.",
      "The Solana audit program anchors roots and final hashes only; it does not verify ZK proofs on-chain.",
    ],
  };
};

export const proofSystemPolicyService = {
  getPolicy: getProofSystemPolicy,
  isOnChainZkVerifierEnabled: () => CIVIC_ON_CHAIN_ZK_VERIFIER_ENABLED,
};

export default proofSystemPolicyService;
