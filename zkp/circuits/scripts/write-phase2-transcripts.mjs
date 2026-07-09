import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = resolve(packageRoot, "build");
const generatedAt =
  process.env.CIVICOS_GROTH16_TRANSCRIPT_GENERATED_AT ||
  new Date().toISOString();
const transcriptDomain = "org.civicos.zkp.groth16.phase2-transcript";
const profile =
  process.env.CIVICOS_GROTH16_ARTIFACT_PROFILE ||
  process.env.CIVICOS_GROTH16_PHASE2_PROFILE ||
  "internal-rc";
const ceremonyName =
  process.env.CIVICOS_GROTH16_CEREMONY_NAME ||
  (profile === "production"
    ? "civicos-production-groth16-phase2-v1"
    : "civicos-internal-rc-groth16-phase2-v1");
const ceremonyUri = process.env.CIVICOS_GROTH16_CEREMONY_URI || null;
const beaconSource = process.env.CIVICOS_GROTH16_BEACON_SOURCE || null;
const beaconValue = process.env.CIVICOS_GROTH16_BEACON_VALUE || null;
const notes =
  process.env.CIVICOS_GROTH16_CEREMONY_NOTES ||
  (profile === "production"
    ? "Production ceremony evidence. Publish this transcript with the final audit material."
    : "Internal release-candidate evidence for devnet/internal testing only.");
const selectedCircuitNames = new Set(
  (process.env.CIVICOS_GROTH16_TRANSCRIPT_CIRCUITS ||
    process.env.CIVICOS_GROTH16_MANIFEST_CIRCUITS ||
    "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean),
);

const circuits = Object.freeze([
  {
    kind: "vote",
    name: "credential_commitment_vote",
    ptauPower: 16,
    circuitId: "civicos-groth16-vote-circuit-v1",
    publicInputSchemaVersion: "civicos-groth16-vote-public-inputs-v1",
    circuitParameters: {
      credentialMerkleDepth: 32,
      maxOptions: 8,
    },
  },
  {
    kind: "tally",
    name: "encrypted_choice_tally",
    ptauPower: 20,
    circuitId: "civicos-groth16-tally-circuit-v1",
    publicInputSchemaVersion: "civicos-groth16-tally-public-inputs-v1",
    circuitParameters: {
      tallyBatchSize: 64,
      maxOptions: 8,
    },
  },
]);

const sha256File = (path) =>
  createHash("sha256").update(readFileSync(path)).digest("hex");
const sha256String = (value) =>
  createHash("sha256").update(value, "utf8").digest("hex");

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
        const normalized = normalizeJsonValue(value[key]);
        if (normalized !== undefined) {
          record[key] = normalized;
        }
        return record;
      }, {});
  }
  return undefined;
};

const canonicalizeJson = (value) => JSON.stringify(normalizeJsonValue(value));
const unixRelativePath = (from, to) => relative(from, to).split(/[\\/]+/).join("/");

const parseContributors = () => {
  const rawJson = process.env.CIVICOS_GROTH16_CONTRIBUTORS_JSON;
  if (rawJson) {
    const parsed = JSON.parse(rawJson);
    if (!Array.isArray(parsed)) {
      throw new Error("CIVICOS_GROTH16_CONTRIBUTORS_JSON must be an array.");
    }
    return parsed.map((entry, index) => {
      if (typeof entry === "string") {
        return { index: index + 1, name: entry };
      }
      if (entry && typeof entry === "object" && typeof entry.name === "string") {
        return { index: index + 1, ...entry };
      }
      throw new Error(
        "CIVICOS_GROTH16_CONTRIBUTORS_JSON entries must be strings or objects with a name.",
      );
    });
  }

  const names = (process.env.CIVICOS_GROTH16_CONTRIBUTORS || "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (names.length > 0) {
    return names.map((name, index) => ({ index: index + 1, name }));
  }

  if (profile === "production") {
    return [];
  }

  return [{ index: 1, name: "CivicOS internal RC" }];
};

const contributors = parseContributors();
if (profile === "production" && contributors.length < 3) {
  throw new Error(
    "Production Phase 2 transcript requires at least three contributors. Set CIVICOS_GROTH16_CONTRIBUTORS or CIVICOS_GROTH16_CONTRIBUTORS_JSON.",
  );
}

mkdirSync(buildDir, { recursive: true });

for (const circuit of circuits) {
  if (selectedCircuitNames.size > 0 && !selectedCircuitNames.has(circuit.name)) {
    continue;
  }

  const paths = {
    ptau: resolve(buildDir, `pot${circuit.ptauPower}_final.ptau`),
    r1cs: resolve(buildDir, `${circuit.name}.r1cs`),
    provingKey: resolve(buildDir, `${circuit.name}_final.zkey`),
    verifierKey: resolve(buildDir, `${circuit.name}.vkey.json`),
    witnessWasm: resolve(buildDir, `${circuit.name}_js/${circuit.name}.wasm`),
  };

  for (const [role, path] of Object.entries(paths)) {
    if (!existsSync(path)) {
      throw new Error(`${role} artifact is missing for ${circuit.name}: ${path}`);
    }
  }

  const transcript = {
    version: "civicos-groth16-phase2-transcript-v1",
    profile,
    ceremonyName,
    ceremonyUri,
    generatedAt,
    proofSystem: "groth16",
    curve: "bn254",
    hashSuite: "poseidon-bn254-v1",
    circuitId: circuit.circuitId,
    circuitName: circuit.name,
    artifactKind: circuit.kind,
    publicInputSchemaVersion: circuit.publicInputSchemaVersion,
    circuitParameters: circuit.circuitParameters,
    phase1: {
      ptauPower: circuit.ptauPower,
      ptauPath: unixRelativePath(packageRoot, paths.ptau),
      ptauHash: sha256File(paths.ptau),
    },
    phase2: {
      contributionCount: contributors.length,
      contributors,
      beacon:
        beaconSource || beaconValue
          ? {
              source: beaconSource,
              value: beaconValue,
            }
          : null,
      provingKeyPath: unixRelativePath(packageRoot, paths.provingKey),
      provingKeyHash: sha256File(paths.provingKey),
      verifierKeyPath: unixRelativePath(packageRoot, paths.verifierKey),
      verifierKeyHash: sha256File(paths.verifierKey),
    },
    artifacts: {
      r1csHash: sha256File(paths.r1cs),
      witnessWasmHash: sha256File(paths.witnessWasm),
    },
    verificationCommands: [
      `snarkjs powersoftau verify build/pot${circuit.ptauPower}_final.ptau`,
      `snarkjs zkey verify build/${circuit.name}.r1cs build/pot${circuit.ptauPower}_final.ptau build/${circuit.name}_final.zkey`,
      `snarkjs groth16 verify build/${circuit.name}.vkey.json test-vectors/${circuit.name}.valid.public.proof.json test-vectors/${circuit.name}.valid.proof.json`,
    ],
    notes,
  };

  const transcriptHash = sha256String(
    `${transcriptDomain}|${canonicalizeJson(transcript)}`,
  );
  const transcriptPath = resolve(buildDir, `${circuit.name}.phase2-transcript.json`);
  const transcriptHashPath = resolve(
    buildDir,
    `${circuit.name}.phase2-transcript-hash.txt`,
  );

  writeFileSync(transcriptPath, `${JSON.stringify(transcript, null, 2)}\n`);
  writeFileSync(transcriptHashPath, `${transcriptHash}\n`);

  console.log(`${circuit.circuitId}`);
  console.log(`  transcript: ${transcriptPath}`);
  console.log(`  transcriptHash: ${transcriptHash}`);
}
