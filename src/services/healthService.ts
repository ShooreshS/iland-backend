import { env } from "../config/env";
import { getSupabaseAdminClient } from "../db/supabaseClient";
import {
  getGroth16VerifierConfig,
  isGroth16VoteVerifierConfigured,
} from "./groth16ProofVerifierService";
import {
  getGroth16TallyVerifierConfig,
  isGroth16TallyVerifierConfigured,
} from "./groth16TallyProofVerifierService";
import { getGroth16TallyProverArtifactStatus } from "./groth16TallyProverService";
import { getBallotCustodyPolicy } from "./ballotCustodyPolicyService";
import { getZkpReleasePolicy } from "./zkpReleasePolicyService";
import zkpTallyJobService from "./zkpTallyJobService";

const startedAt = Date.now();

export const getHealthStatus = () => ({
  status: "ok" as const,
  version: "0.0.86",
  environment: env.nodeEnv,
  timestamp: new Date().toISOString(),
  uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
});

export const getSupabaseHealthStatus = async () => {
  const supabase = getSupabaseAdminClient();

  if (!supabase) {
    return {
      ok: false,
      status: "not_configured" as const,
      provider: "supabase" as const,
      check: "auth.admin.listUsers",
      message:
        "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are not configured.",
    };
  }

  const { error } = await supabase.auth.admin.listUsers({
    page: 1,
    perPage: 1,
  });

  if (error) {
    return {
      ok: false,
      status: "degraded" as const,
      provider: "supabase" as const,
      check: "auth.admin.listUsers",
      message: error.message,
    };
  }

  return {
    ok: true,
    status: "ok" as const,
    provider: "supabase" as const,
    check: "auth.admin.listUsers",
    message: "Supabase admin API reachable.",
  };
};

export const getZkpHealthStatus = async () => {
  const vote = getGroth16VerifierConfig();
  const tally = getGroth16TallyVerifierConfig();
  const ballotCustody = getBallotCustodyPolicy();
  const releasePolicy = getZkpReleasePolicy();
  const tallyWorker = await zkpTallyJobService.getQueueHealth();
  const voteConfigured = isGroth16VoteVerifierConfigured(vote);
  const tallyConfigured = isGroth16TallyVerifierConfigured(tally);
  const tallyProver = getGroth16TallyProverArtifactStatus(tally);
  const releaseGateOk =
    releasePolicy.releaseChannel === "private_beta" ||
    releasePolicy.gates.publicDevnetV01Allowed;
  const tallyWorkerOk =
    env.zkp.tallyWorker.proverMode !== "worker" ||
    !env.zkp.tallyWorker.requiredForProduction ||
    Boolean(tallyWorker.configured && tallyWorker.workerHeartbeatFresh);
  const ok =
    voteConfigured &&
    tallyConfigured &&
    tallyProver.configured &&
    releaseGateOk &&
    tallyWorkerOk;

  return {
    ok,
    status: ok ? "ok" as const : "degraded" as const,
    provider: "zkp" as const,
    checks: {
      voteGroth16Verifier: {
        enabled: vote.voteVerifierEnabled,
        configured: voteConfigured,
        circuitId: vote.voteCircuitId,
        verifierKeyHash: vote.voteVerifierKeyHash,
        publicInputSchemaVersion: vote.publicInputSchemaVersion,
        trustedSetupTranscriptHash: vote.trustedSetupTranscriptHash,
        artifactManifestPath: vote.voteArtifactManifestPath,
        artifactManifestHash: vote.voteArtifactManifestHash,
        artifactManifestStatus: vote.voteArtifactManifestStatus,
        artifactManifestError: vote.voteArtifactManifestError,
      },
      tallyGroth16Verifier: {
        enabled: tally.tallyVerifierEnabled,
        configured: tallyConfigured,
        circuitId: tally.tallyCircuitId,
        verifierKeyHash: tally.tallyVerifierKeyHash,
        publicInputSchemaVersion: tally.tallyPublicInputSchemaVersion,
        trustedSetupTranscriptHash: tally.tallyTrustedSetupTranscriptHash,
        artifactManifestPath: tally.tallyArtifactManifestPath,
        artifactManifestHash: tally.tallyArtifactManifestHash,
        artifactManifestStatus: tally.tallyArtifactManifestStatus,
        artifactManifestError: tally.tallyArtifactManifestError,
      },
      tallyGroth16Prover: tallyProver,
      tallyWorker,
      releasePolicy,
      ballotCustody: {
        version: ballotCustody.version,
        mode: ballotCustody.mode,
        releaseMode: ballotCustody.releaseMode,
        decryptor: ballotCustody.decryptor,
        operatorTrusted: ballotCustody.operatorTrusted,
        threshold: ballotCustody.threshold,
        backendCanDecryptBallots: ballotCustody.backendCanDecryptBallots,
        liveProvisionalPerOptionResults:
          ballotCustody.liveProvisionalPerOptionResults,
        acceptedVoteCountPublicDuringVoting:
          ballotCustody.acceptedVoteCountPublicDuringVoting,
        publicSecretBallotClaimAllowed:
          ballotCustody.publicSecretBallotClaimAllowed,
        privateKeyMaterialExposedByApi:
          ballotCustody.privateKeyMaterialExposedByApi,
        productionGaps: ballotCustody.productionGaps,
      },
    },
  };
};
