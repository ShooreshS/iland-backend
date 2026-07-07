import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

import {
  GROTH16_ARTIFACT_MANIFEST_VERSION,
  hashGroth16ArtifactManifest,
  type Groth16ArtifactManifest,
} from "../src/services/groth16ArtifactManifestService";
import {
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
  CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
  CIVIC_PRODUCTION_PROOF_PROTOCOL,
  CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
  CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  hashGroth16VotePublicInputs,
  type Groth16VoteProofEnvelopeDto,
  type Groth16VotePublicInputsDto,
} from "../src/services/groth16ProofVerifierService";
import {
  CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
  CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  hashGroth16TallyPublicInputs,
  type Groth16TallyProofEnvelopeDto,
  type Groth16TallyPublicInputsDto,
} from "../src/services/groth16TallyProofVerifierService";
import { fieldElementToHex64 } from "../src/services/poseidonBn254Service";

const repoRoot = resolve(import.meta.dir, "..");
const circuitsRoot = resolve(repoRoot, "zkp/circuits");
const buildRoot = resolve(circuitsRoot, "build");
const vectorsRoot = resolve(circuitsRoot, "test-vectors");
const fixturesRoot = resolve(repoRoot, "src/services/__fixtures__");

const sha256Hex = (path: string): string =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

const readJson = <T>(path: string): T =>
  JSON.parse(readFileSync(path, "utf8")) as T;

const writeJson = (path: string, value: unknown): void => {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

const relativeArtifactPath = (fixtureDir: string, artifactPath: string): string =>
  relative(fixtureDir, artifactPath).replaceAll("\\", "/");

const buildManifest = (params: {
  artifactKind: "vote" | "tally";
  circuitId: string;
  publicInputSchemaVersion: string;
  fixtureDir: string;
  verificationKeyPath: string;
  provingKeyPath: string;
  wasmPath: string;
  notes: string;
}): Groth16ArtifactManifest => {
  const verifierKeyHash = sha256Hex(params.verificationKeyPath);
  const provingKeyHash = sha256Hex(params.provingKeyPath);
  const wasmHash = sha256Hex(params.wasmPath);

  return {
    version: GROTH16_ARTIFACT_MANIFEST_VERSION,
    artifactKind: params.artifactKind,
    circuitId: params.circuitId,
    proofSystem: "groth16",
    protocol: "groth16",
    curve: "bn254",
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    publicInputSchemaVersion: params.publicInputSchemaVersion,
    trustedSetupTranscriptHash: provingKeyHash,
    verifierKeyHash,
    provingKeyHash,
    wasmOrNativeArtifactHash: wasmHash,
    artifacts: [
      {
        role: "verification_key",
        path: relativeArtifactPath(params.fixtureDir, params.verificationKeyPath),
        sha256: verifierKeyHash,
        format: "snarkjs-vkey-json",
      },
      {
        role: "proving_key",
        path: relativeArtifactPath(params.fixtureDir, params.provingKeyPath),
        sha256: provingKeyHash,
        format: "zkey",
      },
      {
        role: "witness_wasm",
        path: relativeArtifactPath(params.fixtureDir, params.wasmPath),
        sha256: wasmHash,
        format: "wasm",
      },
    ],
    generatedAt: "2026-07-07T00:00:00.000Z",
    notes: params.notes,
  };
};

const writeManifest = (fixtureDir: string, filename: string, manifest: Groth16ArtifactManifest) => {
  const manifestHash = hashGroth16ArtifactManifest(manifest);
  writeJson(resolve(fixtureDir, filename), manifest);
  writeFileSync(
    resolve(fixtureDir, filename.replace(".json", "-hash.txt")),
    `${manifestHash}\n`,
  );
  return manifestHash;
};

const generateVoteFixture = (): void => {
  const fixtureDir = resolve(fixturesRoot, "groth16-vote");
  mkdirSync(fixtureDir, { recursive: true });

  const publicByName = readJson<Record<string, string>>(
    resolve(vectorsRoot, "credential_commitment_vote.valid.public.named.json"),
  );
  const proof = readJson<Groth16VoteProofEnvelopeDto["proof"]>(
    resolve(vectorsRoot, "credential_commitment_vote.valid.proof.json"),
  );
  const publicSignals = readJson<string[]>(
    resolve(vectorsRoot, "credential_commitment_vote.valid.public.proof.json"),
  );

  const verificationKeyPath = resolve(buildRoot, "credential_commitment_vote.vkey.json");
  const fixtureVerificationKeyPath = resolve(
    fixtureDir,
    "credential_commitment_vote.vkey.json",
  );
  writeFileSync(fixtureVerificationKeyPath, readFileSync(verificationKeyPath));

  const manifest = buildManifest({
    artifactKind: "vote",
    circuitId: "civicos-groth16-vote-circuit-v1",
    publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
    fixtureDir,
    verificationKeyPath: fixtureVerificationKeyPath,
    provingKeyPath: resolve(buildRoot, "credential_commitment_vote_final.zkey"),
    wasmPath: resolve(
      buildRoot,
      "credential_commitment_vote_js/credential_commitment_vote.wasm",
    ),
    notes:
      "Local development fixture for backend snarkjs verifier tests only. Not a production ceremony artifact.",
  });

  const publicInputs: Groth16VotePublicInputsDto = {
    version: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
    pollId: publicByName.pollId,
    pollPolicyHash: fieldElementToHex64(publicByName.pollPolicyHash),
    credentialSchemaHash: fieldElementToHex64(publicByName.credentialSchemaHash),
    optionSetHash: fieldElementToHex64(publicByName.optionSetHash),
    credentialRoot: fieldElementToHex64(publicByName.credentialRoot),
    nullifier: fieldElementToHex64(publicByName.nullifier),
    voteCommitment: fieldElementToHex64(publicByName.voteCommitment),
    encryptedVoteHash: fieldElementToHex64(publicByName.encryptedVoteHash),
    verificationMethodVersion: "civicos-mobile-verification-v1",
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: manifest.circuitId,
    verifierKeyHash: manifest.verifierKeyHash,
    publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  };
  const envelope: Groth16VoteProofEnvelopeDto = {
    version: CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
    protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: manifest.circuitId,
    verifierKeyHash: manifest.verifierKeyHash,
    publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
    proof,
    publicInputs,
    publicInputsHash: hashGroth16VotePublicInputs(publicInputs),
  };

  writeManifest(fixtureDir, "credential_commitment_vote.manifest.json", manifest);
  writeJson(resolve(fixtureDir, "credential_commitment_vote.envelope.json"), envelope);
  writeJson(resolve(fixtureDir, "credential_commitment_vote.public.json"), publicSignals);
  writeFileSync(
    resolve(fixtureDir, "README.md"),
    "# Groth16 Vote Verifier Fixture\n\nLocal development fixture for backend snarkjs verification tests. It was generated from the local CredentialCommitmentVote circuit package and must not be used as a production ceremony artifact.\n",
  );
};

const generateTallyFixture = async (): Promise<void> => {
  const fixtureDir = resolve(fixturesRoot, "groth16-tally");
  mkdirSync(fixtureDir, { recursive: true });

  const publicByName = readJson<Record<string, string>>(
    resolve(vectorsRoot, "encrypted_choice_tally.valid.public.named.json"),
  );
  const proof = readJson<Groth16TallyProofEnvelopeDto["proof"]>(
    resolve(vectorsRoot, "encrypted_choice_tally.valid.proof.json"),
  );
  const publicSignals = readJson<string[]>(
    resolve(vectorsRoot, "encrypted_choice_tally.valid.public.proof.json"),
  );

  const verificationKeyPath = resolve(buildRoot, "encrypted_choice_tally.vkey.json");
  const fixtureVerificationKeyPath = resolve(
    fixtureDir,
    "encrypted_choice_tally.vkey.json",
  );
  writeFileSync(fixtureVerificationKeyPath, readFileSync(verificationKeyPath));

  const manifest = buildManifest({
    artifactKind: "tally",
    circuitId: "civicos-groth16-tally-circuit-v1",
    publicInputSchemaVersion: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    fixtureDir,
    verificationKeyPath: fixtureVerificationKeyPath,
    provingKeyPath: resolve(buildRoot, "encrypted_choice_tally_final.zkey"),
    wasmPath: resolve(buildRoot, "encrypted_choice_tally_js/encrypted_choice_tally.wasm"),
    notes:
      "Local one-vote/two-option development fixture for backend snarkjs verifier tests only. Not a production ceremony artifact.",
  });

  const publicInputs: Groth16TallyPublicInputsDto = {
    version: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    pollId: publicByName.pollId,
    pollPolicyHash: fieldElementToHex64(publicByName.pollPolicyHash),
    credentialSchemaHash: fieldElementToHex64(publicByName.credentialSchemaHash),
    optionSetHash: fieldElementToHex64(publicByName.optionSetHash),
    nullifierRoot: fieldElementToHex64(publicByName.nullifierRoot),
    voteCommitmentRoot: fieldElementToHex64(publicByName.voteCommitmentRoot),
    encryptedVoteRoot: fieldElementToHex64(publicByName.encryptedVoteRoot),
    acceptedVoteCount: Number(publicByName.acceptedVoteCount),
    optionResults: [
      { optionId: "option-a", count: 0 },
      { optionId: "option-b", count: 1 },
    ],
    optionCountsHash: fieldElementToHex64(publicByName.optionCountsHash),
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: manifest.circuitId,
    verifierKeyHash: manifest.verifierKeyHash,
    publicInputSchemaVersion: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  };
  const envelope: Groth16TallyProofEnvelopeDto = {
    version: CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
    protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: manifest.circuitId,
    verifierKeyHash: manifest.verifierKeyHash,
    publicInputSchemaVersion: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    proof,
    publicInputs,
    publicInputsHash: hashGroth16TallyPublicInputs(publicInputs),
  };

  writeManifest(fixtureDir, "encrypted_choice_tally.manifest.json", manifest);
  writeJson(resolve(fixtureDir, "encrypted_choice_tally.envelope.json"), envelope);
  writeJson(resolve(fixtureDir, "encrypted_choice_tally.public.json"), publicSignals);
  writeFileSync(
    resolve(fixtureDir, "README.md"),
    "# Groth16 Tally Verifier Fixture\n\nLocal one-vote/two-option development fixture for backend snarkjs verification tests. It was generated from the local EncryptedChoiceTally circuit package and must not be used as a production ceremony artifact.\n",
  );
};

generateVoteFixture();
await generateTallyFixture();

console.log("Generated backend Groth16 vote and tally fixtures.");
