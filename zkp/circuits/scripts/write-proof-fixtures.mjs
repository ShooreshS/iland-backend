import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const backendRoot = resolve(packageRoot, "../..");
const vectorDir = resolve(packageRoot, "test-vectors");
const fixtureRoot = resolve(backendRoot, "src/services/__fixtures__");

const selectedCircuitNames = new Set(
  (process.env.CIVICOS_GROTH16_FIXTURE_CIRCUITS || "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean),
);

const circuits = Object.freeze([
  {
    kind: "vote",
    name: "credential_commitment_vote",
    outputDir: "groth16-vote",
    envelopeVersion: "civicos-groth16-vote-proof-envelope-v1",
    publicInputSchemaVersion: "civicos-groth16-vote-public-inputs-v1",
    publicInputDomain: "org.civicos.zkp|groth16-vote-public-inputs",
    circuitId: "civicos-groth16-vote-circuit-v1",
    buildPublicInputs: (named, manifest) => ({
      version: "civicos-groth16-vote-public-inputs-v1",
      pollId: named.pollId,
      pollPolicyHash: fieldToHex64(named.pollPolicyHash),
      credentialSchemaHash: fieldToHex64(named.credentialSchemaHash),
      optionSetHash: fieldToHex64(named.optionSetHash),
      optionCount: Number(named.optionCount),
      credentialRoot: fieldToHex64(named.credentialRoot),
      nullifier: fieldToHex64(named.nullifier),
      voteCommitment: fieldToHex64(named.voteCommitment),
      encryptedVoteHash: "a".repeat(64),
      encryptedVoteCommitment: fieldToHex64(named.encryptedVoteCommitment),
      verificationMethodVersion: "civicos-mobile-verification-v1",
      proofSystemVersion: "civicos-zk-proof-v1",
      hashSuite: "poseidon-bn254-v1",
      circuitId: manifest.circuitId,
      verifierKeyHash: manifest.verifierKeyHash,
      publicInputSchemaVersion: manifest.publicInputSchemaVersion,
    }),
  },
  {
    kind: "tally",
    name: "encrypted_choice_tally",
    outputDir: "groth16-tally",
    envelopeVersion: "civicos-groth16-tally-proof-envelope-v1",
    publicInputSchemaVersion: "civicos-groth16-tally-public-inputs-v1",
    publicInputDomain: "org.civicos.zkp|groth16-tally-public-inputs",
    circuitId: "civicos-groth16-tally-circuit-v1",
    buildPublicInputs: (named, manifest) => ({
      version: "civicos-groth16-tally-public-inputs-v1",
      pollId: named.pollId,
      pollPolicyHash: fieldToHex64(named.pollPolicyHash),
      credentialSchemaHash: fieldToHex64(named.credentialSchemaHash),
      optionSetHash: fieldToHex64(named.optionSetHash),
      optionCount: Number(named.optionCount),
      nullifierRoot: fieldToHex64(named.nullifierRoot),
      voteCommitmentRoot: fieldToHex64(named.voteCommitmentRoot),
      encryptedVoteRoot: fieldToHex64(named.encryptedVoteRoot),
      acceptedVoteCount: Number(named.acceptedVoteCount),
      optionResults: [
        { optionId: "option-0", count: 0 },
        { optionId: "option-1", count: 1 },
        { optionId: "option-2", count: 1 },
        { optionId: "option-3", count: 1 },
      ],
      optionCountsHash: fieldToHex64(named.optionCountsHash),
      proofSystemVersion: "civicos-zk-proof-v1",
      hashSuite: "poseidon-bn254-v1",
      circuitId: manifest.circuitId,
      verifierKeyHash: manifest.verifierKeyHash,
      publicInputSchemaVersion: manifest.publicInputSchemaVersion,
    }),
  },
]);

const sha256Hex = (value) => createHash("sha256").update(value, "utf8").digest("hex");

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

const writeJson = (path, value) => {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

const normalizeJsonValue = (value) => {
  if (value === null) {
    return null;
  }
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(normalizeJsonValue);
  }
  if (typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((record, key) => {
        if (value[key] !== undefined) {
          record[key] = normalizeJsonValue(value[key]);
        }
        return record;
      }, {});
  }
  return undefined;
};

const canonicalizeJson = (value) => JSON.stringify(normalizeJsonValue(value));

const fieldToHex64 = (value) => BigInt(value).toString(16).padStart(64, "0");

for (const circuit of circuits) {
  if (selectedCircuitNames.size > 0 && !selectedCircuitNames.has(circuit.name)) {
    continue;
  }

  const fixtureDir = resolve(fixtureRoot, circuit.outputDir);
  mkdirSync(fixtureDir, { recursive: true });

  const manifest = readJson(resolve(fixtureDir, `${circuit.name}.manifest.json`));
  const proof = readJson(resolve(vectorDir, `${circuit.name}.valid.proof.json`));
  const publicSignals = readJson(
    resolve(vectorDir, `${circuit.name}.valid.public.proof.json`),
  );
  const namedPublicSignals = readJson(
    resolve(vectorDir, `${circuit.name}.valid.public.named.json`),
  );
  const publicInputs = circuit.buildPublicInputs(namedPublicSignals, manifest);
  const publicInputsHash = sha256Hex(
    `${circuit.publicInputDomain}|${canonicalizeJson(publicInputs)}`,
  );
  const envelope = {
    version: circuit.envelopeVersion,
    protocol: "groth16",
    proofSystemVersion: "civicos-zk-proof-v1",
    status: "generated",
    hashSuite: "poseidon-bn254-v1",
    circuitId: manifest.circuitId,
    verifierKeyHash: manifest.verifierKeyHash,
    publicInputSchemaVersion: manifest.publicInputSchemaVersion,
    proof,
    publicInputs,
    publicInputsHash,
  };

  writeJson(resolve(fixtureDir, `${circuit.name}.public.json`), publicSignals);
  writeJson(resolve(fixtureDir, `${circuit.name}.envelope.json`), envelope);

  console.log(`${circuit.circuitId}`);
  console.log(`  fixture: ${resolve(fixtureDir, `${circuit.name}.envelope.json`)}`);
  console.log(`  publicInputsHash: ${publicInputsHash}`);
}
