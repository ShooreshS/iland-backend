import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const backendRoot = resolve(packageRoot, "../..");
const buildDir = resolve(packageRoot, "build");
const generatedAt =
  process.env.CIVICOS_GROTH16_MANIFEST_GENERATED_AT ||
  new Date().toISOString();
const manifestDomain = "org.civicos.zkp.groth16.artifact-manifest";
const transcriptDomain = "org.civicos.zkp.groth16.internal-rc-transcript";

const outputRoot = resolve(backendRoot, "src/zkp-artifacts");
const fixtureRoot = resolve(backendRoot, "src/services/__fixtures__");

const circuits = Object.freeze([
  {
    kind: "vote",
    name: "credential_commitment_vote",
    outputDir: "groth16-vote",
    ptauPower: 16,
    circuitId: "civicos-groth16-vote-circuit-v1",
    publicInputSchemaVersion: "civicos-groth16-vote-public-inputs-v1",
    circuitParameters: {
      credentialMerkleDepth: 32,
      maxOptions: 8,
    },
    notes:
      "Internal release-candidate artifact for credential-commitment-only v1 testing. Not a final audited multi-contributor production ceremony.",
  },
  {
    kind: "tally",
    name: "encrypted_choice_tally",
    outputDir: "groth16-tally",
    ptauPower: 20,
    circuitId: "civicos-groth16-tally-circuit-v1",
    publicInputSchemaVersion: "civicos-groth16-tally-public-inputs-v1",
    circuitParameters: {
      tallyBatchSize: 64,
      maxOptions: 8,
    },
    notes:
      "Internal release-candidate artifact for 64-vote x 8-option tally testing. Not a final audited multi-contributor production ceremony.",
  },
]);
const selectedCircuitNames = new Set(
  (process.env.CIVICOS_GROTH16_MANIFEST_CIRCUITS || "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean),
);

const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const sha256String = (value) => createHash("sha256").update(value, "utf8").digest("hex");

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

const hashManifest = (manifest) =>
  sha256String(`${manifestDomain}|${canonicalizeJson(manifest)}`);

const artifactEntry = ({ role, path, sha256, format }) => ({
  role,
  path,
  sha256,
  format,
  bytes: statSync(path).size,
});

const unixRelativePath = (from, to) => relative(from, to).split(/[\\/]+/).join("/");

for (const circuit of circuits) {
  if (selectedCircuitNames.size > 0 && !selectedCircuitNames.has(circuit.name)) {
    continue;
  }

  const artifactDir = resolve(outputRoot, circuit.outputDir);
  const fixtureDir = resolve(fixtureRoot, circuit.outputDir);
  mkdirSync(artifactDir, { recursive: true });
  mkdirSync(fixtureDir, { recursive: true });

  const vkeySource = resolve(buildDir, `${circuit.name}.vkey.json`);
  const zkeyPath = resolve(buildDir, `${circuit.name}_final.zkey`);
  const wasmPath = resolve(buildDir, `${circuit.name}_js/${circuit.name}.wasm`);
  const r1csPath = resolve(buildDir, `${circuit.name}.r1cs`);
  const ptauPath = resolve(buildDir, `pot${circuit.ptauPower}_final.ptau`);
  const vkeyPath = resolve(artifactDir, `${circuit.name}.vkey.json`);
  copyFileSync(vkeySource, vkeyPath);
  copyFileSync(vkeySource, resolve(fixtureDir, `${circuit.name}.vkey.json`));

  const verifierKeyHash = sha256File(vkeyPath);
  const provingKeyHash = sha256File(zkeyPath);
  const wasmHash = sha256File(wasmPath);
  const r1csHash = sha256File(r1csPath);
  const phase1TranscriptHash = sha256File(ptauPath);
  const trustedSetupTranscriptHash = sha256String(
    `${transcriptDomain}|${canonicalizeJson({
      circuitId: circuit.circuitId,
      phase1TranscriptHash,
      provingKeyHash,
      r1csHash,
      verifierKeyHash,
      wasmHash,
    })}`,
  );

  const manifest = {
    version: "civicos-groth16-artifact-manifest-v1",
    artifactKind: circuit.kind,
    circuitId: circuit.circuitId,
    proofSystem: "groth16",
    protocol: "groth16",
    curve: "bn254",
    hashSuite: "poseidon-bn254-v1",
    publicInputSchemaVersion: circuit.publicInputSchemaVersion,
    trustedSetupTranscriptHash,
    verifierKeyHash,
    provingKeyHash,
    wasmOrNativeArtifactHash: wasmHash,
    circuitParameters: circuit.circuitParameters,
    artifacts: [
      {
        ...artifactEntry({
          role: "verification_key",
          path: vkeyPath,
          sha256: verifierKeyHash,
          format: "snarkjs-vkey-json",
        }),
        path: `${circuit.name}.vkey.json`,
      },
      {
        ...artifactEntry({
          role: "proving_key",
          path: zkeyPath,
          sha256: provingKeyHash,
          format: "zkey",
        }),
        path: unixRelativePath(artifactDir, zkeyPath),
      },
      {
        ...artifactEntry({
          role: "witness_wasm",
          path: wasmPath,
          sha256: wasmHash,
          format: "wasm",
        }),
        path: unixRelativePath(artifactDir, wasmPath),
      },
      {
        ...artifactEntry({
          role: "r1cs",
          path: r1csPath,
          sha256: r1csHash,
          format: "r1cs",
        }),
        path: unixRelativePath(artifactDir, r1csPath),
      },
    ],
    trustedSetup: {
      ceremony: "internal-release-candidate-single-contributor",
      phase1TranscriptHash,
      phase2TranscriptHash: trustedSetupTranscriptHash,
      contributionCount: 1,
      notes:
        "For devnet/internal testing only. Replace with a documented multi-contributor production ceremony before mainnet production use.",
    },
    generatedAt,
    notes: circuit.notes,
  };

  const manifestHash = hashManifest(manifest);
  writeFileSync(
    resolve(artifactDir, `${circuit.name}.manifest.json`),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  writeFileSync(
    resolve(artifactDir, `${circuit.name}.manifest-hash.txt`),
    `${manifestHash}\n`,
  );
  writeFileSync(
    resolve(fixtureDir, `${circuit.name}.manifest.json`),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  writeFileSync(
    resolve(fixtureDir, `${circuit.name}.manifest-hash.txt`),
    `${manifestHash}\n`,
  );

  console.log(`${circuit.circuitId}`);
  console.log(`  manifest: ${resolve(artifactDir, `${circuit.name}.manifest.json`)}`);
  console.log(`  manifestHash: ${manifestHash}`);
  console.log(`  verifierKeyHash: ${verifierKeyHash}`);
  console.log(`  trustedSetupTranscriptHash: ${trustedSetupTranscriptHash}`);
}
