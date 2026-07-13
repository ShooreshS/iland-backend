import { env } from "../config/env";
import {
  getGroth16VerifierConfig,
  isGroth16VoteVerifierConfigured,
} from "./groth16ProofVerifierService";
import {
  getGroth16TallyVerifierConfig,
  isGroth16TallyVerifierConfigured,
} from "./groth16TallyProofVerifierService";
import type { Groth16ArtifactManifest } from "./groth16ArtifactManifestService";

export const ZKP_RELEASE_POLICY_VERSION =
  "civicos-zkp-release-policy-v1" as const;

const FINAL_CEREMONY_MIN_CONTRIBUTIONS = 3;

type ManifestSummary = Readonly<{
  artifactKind: "vote" | "tally";
  status:
    | "not_configured"
    | "loaded"
    | "invalid"
    | "hash_mismatch"
    | "kind_mismatch"
    | "config_mismatch";
  circuitId: string | null;
  publicInputSchemaVersion: string | null;
  verifierKeyHash: string | null;
  trustedSetupTranscriptHash: string | null;
  artifactManifestHash: string | null;
  ceremony: string | null;
  contributionCount: number | null;
  finalCeremonyArtifact: boolean;
}>;

export type ZkpReleasePolicy = Readonly<{
  version: typeof ZKP_RELEASE_POLICY_VERSION;
  releaseChannel: "private_beta" | "public_devnet_v0_1" | "mainnet_v0_1_1";
  artifactStage: "internal_rc" | "ceremony_pending" | "production_final";
  publicDevnetVersion: "0.1";
  mainnetMigrationVersion: "0.1.1";
  publicDevnetReleaseConfirmed: boolean;
  solanaCluster: string;
  mainnetConfirmed: boolean;
  humanCeremony: Readonly<{
    requiredBeforeMainnet: true;
    minimumIndependentContributors: typeof FINAL_CEREMONY_MIN_CONTRIBUTIONS;
    status: "pending_contributor_outputs" | "complete";
  }>;
  manifests: Readonly<{
    vote: ManifestSummary;
    tally: ManifestSummary;
  }>;
  gates: Readonly<{
    verifierConfigured: boolean;
    publicDevnetV01Allowed: boolean;
    mainnetV011Allowed: boolean;
    finalArtifactsPinned: boolean;
    blockedReasons: readonly string[];
  }>;
}>;

const isFinalCeremonyManifest = (
  manifest: Groth16ArtifactManifest | null,
): boolean => {
  if (!manifest) {
    return false;
  }

  const ceremony = manifest.trustedSetup?.ceremony ?? "";
  const contributionCount = manifest.trustedSetup?.contributionCount ?? 0;
  return (
    contributionCount >= FINAL_CEREMONY_MIN_CONTRIBUTIONS &&
    !ceremony.includes("internal-release-candidate")
  );
};

const summarizeManifest = (input: {
  artifactKind: "vote" | "tally";
  status: ManifestSummary["status"];
  manifest: Groth16ArtifactManifest | null;
  circuitId: string | null;
  publicInputSchemaVersion: string | null;
  verifierKeyHash: string | null;
  trustedSetupTranscriptHash: string | null;
  artifactManifestHash: string | null;
}): ManifestSummary =>
  Object.freeze({
    artifactKind: input.artifactKind,
    status: input.status,
    circuitId: input.circuitId,
    publicInputSchemaVersion: input.publicInputSchemaVersion,
    verifierKeyHash: input.verifierKeyHash,
    trustedSetupTranscriptHash: input.trustedSetupTranscriptHash,
    artifactManifestHash: input.artifactManifestHash,
    ceremony: input.manifest?.trustedSetup?.ceremony ?? null,
    contributionCount: input.manifest?.trustedSetup?.contributionCount ?? null,
    finalCeremonyArtifact: isFinalCeremonyManifest(input.manifest),
  });

export const getZkpReleasePolicy = (): ZkpReleasePolicy => {
  const vote = getGroth16VerifierConfig();
  const tally = getGroth16TallyVerifierConfig();
  const voteConfigured = isGroth16VoteVerifierConfigured(vote);
  const tallyConfigured = isGroth16TallyVerifierConfigured(tally);
  const finalArtifactsPinned =
    isFinalCeremonyManifest(vote.voteArtifactManifest) &&
    isFinalCeremonyManifest(tally.tallyArtifactManifest);
  const blockedReasons: string[] = [];

  if (!voteConfigured) {
    blockedReasons.push("Groth16 vote verifier is not fully configured.");
  }

  if (!tallyConfigured) {
    blockedReasons.push("Groth16 tally verifier is not fully configured.");
  }

  if (env.zkp.release.channel === "public_devnet_v0_1") {
    if (env.solanaAudit.cluster !== "devnet") {
      blockedReasons.push("Public v0.1 release must remain on Solana devnet.");
    }

    if (env.solanaAudit.mainnetConfirmed) {
      blockedReasons.push("Public devnet v0.1 must not set mainnet confirmation.");
    }

    if (!env.zkp.release.publicDevnetV01Confirmed) {
      blockedReasons.push(
        "Public devnet v0.1 release requires ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED=true.",
      );
    }
  }

  if (env.zkp.release.channel === "mainnet_v0_1_1") {
    if (env.solanaAudit.cluster !== "mainnet-beta") {
      blockedReasons.push("Mainnet v0.1.1 release requires mainnet-beta.");
    }

    if (!env.solanaAudit.mainnetConfirmed) {
      blockedReasons.push("Mainnet v0.1.1 release requires mainnet confirmation.");
    }

    if (env.zkp.release.artifactStage !== "production_final") {
      blockedReasons.push(
        "Mainnet v0.1.1 release requires production-final artifact stage.",
      );
    }

    if (!finalArtifactsPinned) {
      blockedReasons.push(
        "Mainnet v0.1.1 release requires final multi-contributor ceremony artifacts.",
      );
    }
  }

  const verifierConfigured = voteConfigured && tallyConfigured;
  const publicDevnetV01Allowed =
    env.zkp.release.channel === "public_devnet_v0_1" &&
    env.solanaAudit.cluster === "devnet" &&
    !env.solanaAudit.mainnetConfirmed &&
    env.zkp.release.publicDevnetV01Confirmed &&
    verifierConfigured;
  const mainnetV011Allowed =
    env.zkp.release.channel === "mainnet_v0_1_1" &&
    env.solanaAudit.cluster === "mainnet-beta" &&
    env.solanaAudit.mainnetConfirmed &&
    env.zkp.release.artifactStage === "production_final" &&
    verifierConfigured &&
    finalArtifactsPinned;

  return Object.freeze({
    version: ZKP_RELEASE_POLICY_VERSION,
    releaseChannel: env.zkp.release.channel,
    artifactStage: env.zkp.release.artifactStage,
    publicDevnetVersion: "0.1",
    mainnetMigrationVersion: "0.1.1",
    publicDevnetReleaseConfirmed: env.zkp.release.publicDevnetV01Confirmed,
    solanaCluster: env.solanaAudit.cluster,
    mainnetConfirmed: env.solanaAudit.mainnetConfirmed,
    humanCeremony: Object.freeze({
      requiredBeforeMainnet: true,
      minimumIndependentContributors: FINAL_CEREMONY_MIN_CONTRIBUTIONS,
      status: finalArtifactsPinned ? "complete" : "pending_contributor_outputs",
    }),
    manifests: Object.freeze({
      vote: summarizeManifest({
        artifactKind: "vote",
        status: vote.voteArtifactManifestStatus,
        manifest: vote.voteArtifactManifest,
        circuitId: vote.voteCircuitId,
        publicInputSchemaVersion: vote.publicInputSchemaVersion,
        verifierKeyHash: vote.voteVerifierKeyHash,
        trustedSetupTranscriptHash: vote.trustedSetupTranscriptHash,
        artifactManifestHash: vote.voteArtifactManifestHash,
      }),
      tally: summarizeManifest({
        artifactKind: "tally",
        status: tally.tallyArtifactManifestStatus,
        manifest: tally.tallyArtifactManifest,
        circuitId: tally.tallyCircuitId,
        publicInputSchemaVersion: tally.tallyPublicInputSchemaVersion,
        verifierKeyHash: tally.tallyVerifierKeyHash,
        trustedSetupTranscriptHash: tally.tallyTrustedSetupTranscriptHash,
        artifactManifestHash: tally.tallyArtifactManifestHash,
      }),
    }),
    gates: Object.freeze({
      verifierConfigured,
      publicDevnetV01Allowed,
      mainnetV011Allowed,
      finalArtifactsPinned,
      blockedReasons: Object.freeze(blockedReasons),
    }),
  });
};

export const zkpReleasePolicyService = {
  getPolicy: getZkpReleasePolicy,
};

export default zkpReleasePolicyService;
