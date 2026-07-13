#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const backendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appRoot = resolve(backendRoot, "../iland");

const files = Object.freeze({
  frozenCircuits: resolve(backendRoot, "zkp/circuits/FROZEN_CIRCUITS_V1.md"),
  phase9Freeze: resolve(backendRoot, "zkp/PHASE9_PRE_CEREMONY_FREEZE.md"),
  voteManifest: resolve(
    backendRoot,
    "src/zkp-artifacts/groth16-vote/credential_commitment_vote.manifest.json",
  ),
  voteManifestHash: resolve(
    backendRoot,
    "src/zkp-artifacts/groth16-vote/credential_commitment_vote.manifest-hash.txt",
  ),
  tallyManifest: resolve(
    backendRoot,
    "src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest.json",
  ),
  tallyManifestHash: resolve(
    backendRoot,
    "src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest-hash.txt",
  ),
  ceremonyReadme: resolve(
    backendRoot,
    "scripts/human-ceremony/coordinator/README-COORDINATOR.md",
  ),
  prepareCeremony: resolve(
    backendRoot,
    "scripts/human-ceremony/coordinator/prepare-ceremony.sh",
  ),
  finalizeCeremony: resolve(
    backendRoot,
    "scripts/human-ceremony/coordinator/finalize-ceremony.sh",
  ),
  appVoteManifest: resolve(
    appRoot,
    "assets/zkp/groth16-vote/credential_commitment_vote.manifest.json",
  ),
  appVoteManifestHash: resolve(
    appRoot,
    "assets/zkp/groth16-vote/credential_commitment_vote.manifest-hash.txt",
  ),
  appMobileArtifacts: resolve(appRoot, "src/identity/mobileGroth16Artifacts.js"),
  appIdentitySecret: resolve(appRoot, "src/identity/identitySecret.js"),
  appZkProofInputs: resolve(appRoot, "src/identity/zkProofInputs.js"),
  appMobileProver: resolve(appRoot, "src/identity/mobileGroth16Prover.js"),
  iosProver: resolve(appRoot, "ios/iland/CivicOSGroth16VoteProver.swift"),
  androidProver: resolve(
    appRoot,
    "android/app/src/main/java/com/shooresh/iland/nativebridge/CivicOSGroth16VoteProverModule.kt",
  ),
});

const blockers = [];
const warnings = [];
const checks = [];

const relative = (file) => file.replace(`${backendRoot}/`, "back/");

const record = (ok, label, details = undefined) => {
  checks.push({ ok, label, ...(details === undefined ? {} : { details }) });
  if (!ok) {
    blockers.push(label);
  }
};

const warn = (label) => {
  warnings.push(label);
  checks.push({ ok: true, warning: true, label });
};

const requireFile = (file) => {
  const ok = existsSync(file);
  record(ok, `required file exists: ${relative(file)}`);
  return ok;
};

const readText = (file) => readFileSync(file, "utf8");
const readJson = (file) => JSON.parse(readText(file));
const sha256File = (file) =>
  createHash("sha256").update(readFileSync(file)).digest("hex");

for (const file of Object.values(files)) {
  requireFile(file);
}

if (blockers.length === 0) {
  const voteManifest = readJson(files.voteManifest);
  const tallyManifest = readJson(files.tallyManifest);
  const appVoteManifest = readJson(files.appVoteManifest);
  const voteManifestHash = readText(files.voteManifestHash).trim();
  const tallyManifestHash = readText(files.tallyManifestHash).trim();
  const appVoteManifestHash = readText(files.appVoteManifestHash).trim();
  const mobileArtifacts = readText(files.appMobileArtifacts);
  const identitySecret = readText(files.appIdentitySecret);
  const zkProofInputs = readText(files.appZkProofInputs);
  const mobileProver = readText(files.appMobileProver);
  const iosProver = readText(files.iosProver);
  const androidProver = readText(files.androidProver);

  record(
    voteManifest.circuitId === "civicos-groth16-vote-circuit-v1",
    "vote circuit id is frozen v1",
    voteManifest.circuitId,
  );
  record(
    voteManifest.publicInputSchemaVersion ===
      "civicos-groth16-vote-public-inputs-v1",
    "vote public input schema is frozen v1",
    voteManifest.publicInputSchemaVersion,
  );
  record(
    voteManifest.circuitParameters?.credentialMerkleDepth === 32,
    "vote credential registry depth is 32",
    voteManifest.circuitParameters,
  );
  record(
    voteManifest.circuitParameters?.maxOptions === 8,
    "vote max options is 8",
    voteManifest.circuitParameters,
  );
  record(
    tallyManifest.circuitId === "civicos-groth16-tally-circuit-v1",
    "tally circuit id is frozen v1",
    tallyManifest.circuitId,
  );
  record(
    tallyManifest.publicInputSchemaVersion ===
      "civicos-groth16-tally-public-inputs-v1",
    "tally public input schema is frozen v1",
    tallyManifest.publicInputSchemaVersion,
  );
  record(
    tallyManifest.circuitParameters?.tallyBatchSize === 64 &&
      tallyManifest.circuitParameters?.maxOptions === 8,
    "tally batch is 64 votes x 8 options",
    tallyManifest.circuitParameters,
  );
  record(
    appVoteManifest.verifierKeyHash === voteManifest.verifierKeyHash &&
      appVoteManifest.provingKeyHash === voteManifest.provingKeyHash &&
      appVoteManifest.trustedSetupTranscriptHash ===
        voteManifest.trustedSetupTranscriptHash,
    "mobile vote manifest pins match backend vote manifest",
  );
  record(
    appVoteManifestHash === voteManifestHash,
    "mobile vote manifest hash matches backend domain manifest hash",
    { backend: voteManifestHash, mobile: appVoteManifestHash },
  );
  record(
    mobileArtifacts.includes(voteManifestHash) &&
      (mobileArtifacts.includes(voteManifest.verifierKeyHash) ||
        mobileArtifacts.includes("verifierKeyHash: voteManifest.verifierKeyHash")) &&
      mobileArtifacts.includes(voteManifest.provingKeyHash),
    "mobile JS artifact bundle pins backend vote hashes",
  );
  record(
    iosProver.includes(voteManifestHash) &&
      iosProver.includes(voteManifest.verifierKeyHash),
    "iOS native prover constants pin backend vote hashes",
  );
  record(
    androidProver.includes(voteManifestHash) &&
      androidProver.includes(voteManifest.verifierKeyHash),
    "Android native prover constants pin backend vote hashes",
  );
  record(
    identitySecret.includes("civicos-identity-secret-v2") &&
      identitySecret.includes("org.civicos.zkp.identity-secret.v2"),
    "identity-secret v2 derivation contract is present",
  );
  record(
    zkProofInputs.includes("civicos-groth16-vote-public-inputs-v1") &&
      zkProofInputs.includes("civicos-encrypted-vote-v1") &&
      zkProofInputs.includes("civicos-encrypted-vote-opening-v1") &&
      zkProofInputs.includes("x25519-hkdf-sha256-aes-256-gcm-v1") &&
      zkProofInputs.includes("poseidon-encrypted-vote-opening-v1"),
    "mobile proof/encrypted-vote payload contract is frozen",
  );
  record(
    mobileProver.includes("CIVIC_CREDENTIAL_MERKLE_DEPTH = 32") &&
      mobileProver.includes("CIVIC_TALLY_MAX_OPTIONS = 8"),
    "mobile prover enforces depth 32 and max 8 options",
  );
  record(
    sha256File(files.appVoteManifest) === sha256File(files.voteManifest),
    "mobile and backend vote manifest files are byte-identical",
  );
  record(
    /^[0-9a-f]{64}$/.test(tallyManifestHash),
    "backend tally manifest domain hash is pinned",
    tallyManifestHash,
  );

  const voteContributions = voteManifest.trustedSetup?.contributionCount ?? 0;
  const tallyContributions = tallyManifest.trustedSetup?.contributionCount ?? 0;
  const finalCeremonyReady =
    voteContributions >= 3 &&
    tallyContributions >= 3 &&
    voteManifest.trustedSetup?.ceremony !==
      "internal-release-candidate-single-contributor" &&
    tallyManifest.trustedSetup?.ceremony !==
      "internal-release-candidate-single-contributor";

  if (!finalCeremonyReady) {
    warn(
      "final multi-contributor ceremony artifacts are pending; this is expected before contributor outputs are returned",
    );
  }

  const report = {
    status:
      blockers.length === 0
        ? finalCeremonyReady
          ? "production_artifacts_ready"
          : "ready_for_human_ceremony"
        : "blocked",
    publicDevnetVersion: "0.1",
    mainnetMigrationVersion: "0.1.1",
    finalHumanCeremonyRequiredBeforeMainnet: true,
    voteManifestHash,
    tallyManifestHash,
    voteTrustedSetup: voteManifest.trustedSetup,
    tallyTrustedSetup: tallyManifest.trustedSetup,
    checks,
    warnings,
    blockers,
  };

  console.log(JSON.stringify(report, null, 2));
  process.exit(blockers.length === 0 ? 0 : 1);
}

console.log(
  JSON.stringify(
    {
      status: "blocked",
      publicDevnetVersion: "0.1",
      mainnetMigrationVersion: "0.1.1",
      finalHumanCeremonyRequiredBeforeMainnet: true,
      checks,
      warnings,
      blockers,
    },
    null,
    2,
  ),
);
process.exit(1);
