#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const backendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const defaultVoteManifestPath =
  "src/zkp-artifacts/groth16-vote/credential_commitment_vote.manifest.json";
const defaultTallyManifestPath =
  "src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest.json";

const voteManifestPath =
  process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH ||
  defaultVoteManifestPath;
const tallyManifestPath =
  process.env.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH ||
  defaultTallyManifestPath;

const readJson = (relativePath) =>
  JSON.parse(readFileSync(resolve(backendRoot, relativePath), "utf8"));
const readHash = (manifestPath) =>
  readFileSync(
    resolve(backendRoot, manifestPath.replace(/\.json$/, "-hash.txt")),
    "utf8",
  )
    .trim()
    .toLowerCase();

const voteManifest = readJson(voteManifestPath);
const tallyManifest = readJson(tallyManifestPath);

const env = {
  ZKP_ARTIFACT_RELEASE_STAGE: "ceremony_pending",
  ZKP_GROTH16_PUBLIC_INPUT_SCHEMA_VERSION:
    voteManifest.publicInputSchemaVersion,
  ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH: readHash(tallyManifestPath),
  ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH: tallyManifestPath,
  ZKP_GROTH16_TALLY_CIRCUIT_ID: tallyManifest.circuitId,
  ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION:
    tallyManifest.publicInputSchemaVersion,
  ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH:
    tallyManifest.trustedSetupTranscriptHash,
  ZKP_GROTH16_TALLY_VERIFIER_ENABLED: "true",
  ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH: tallyManifest.verifierKeyHash,
  ZKP_GROTH16_TRUSTED_SETUP_TRANSCRIPT_HASH:
    voteManifest.trustedSetupTranscriptHash,
  ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH: readHash(voteManifestPath),
  ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH: voteManifestPath,
  ZKP_GROTH16_VOTE_CIRCUIT_ID: voteManifest.circuitId,
  ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION:
    voteManifest.publicInputSchemaVersion,
  ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH:
    voteManifest.trustedSetupTranscriptHash,
  ZKP_GROTH16_VOTE_VERIFIER_ENABLED: "true",
  ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH: voteManifest.verifierKeyHash,
  ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED: "true",
  ZKP_RELEASE_CHANNEL: "public_devnet_v0_1",
};

for (const key of Object.keys(env).sort()) {
  console.log(`${key}=${env[key]}`);
}
