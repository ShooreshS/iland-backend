import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
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
const artifactProfile = process.env.CIVICOS_GROTH16_ARTIFACT_PROFILE || "internal-rc";
const ceremonyName =
  process.env.CIVICOS_GROTH16_CEREMONY_NAME ||
  (artifactProfile === "production"
    ? "civicos-production-groth16-phase2-v1"
    : "internal-release-candidate-single-contributor");
const defaultNotes =
  artifactProfile === "production"
    ? "Production ceremony artifact. Publish the matching Phase 2 transcript and verifier command output with the public audit material."
    : "Internal release-candidate artifact for devnet/internal testing only. Not a final audited multi-contributor production ceremony.";

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
    notes: defaultNotes,
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
    notes: defaultNotes,
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
  const phase2TranscriptPath = resolve(
    buildDir,
    `${circuit.name}.phase2-transcript.json`,
  );
  const phase2TranscriptHashPath = resolve(
    buildDir,
    `${circuit.name}.phase2-transcript-hash.txt`,
  );
  const vkeyPath = resolve(artifactDir, `${circuit.name}.vkey.json`);
  copyFileSync(vkeySource, vkeyPath);
  copyFileSync(vkeySource, resolve(fixtureDir, `${circuit.name}.vkey.json`));

  const verifierKeyHash = sha256File(vkeyPath);
  const provingKeyHash = sha256File(zkeyPath);
  const wasmHash = sha256File(wasmPath);
  const r1csHash = sha256File(r1csPath);
  const phase1TranscriptHash = sha256File(ptauPath);
  const fallbackTrustedSetupTranscriptHash = sha256String(
    `${transcriptDomain}|${canonicalizeJson({
      circuitId: circuit.circuitId,
      phase1TranscriptHash,
      provingKeyHash,
      r1csHash,
      verifierKeyHash,
      wasmHash,
    })}`,
  );
  const phase2Transcript = existsSync(phase2TranscriptPath)
    ? JSON.parse(readFileSync(phase2TranscriptPath, "utf8"))
    : null;
  if (artifactProfile === "production" && !phase2Transcript) {
    throw new Error(
      `Production manifest requires ${phase2TranscriptPath}. Run npm run transcripts after the production ceremony.`,
    );
  }
  if (artifactProfile === "production") {
    const contributionCount = phase2Transcript?.phase2?.contributionCount;
    if (typeof contributionCount !== "number" || contributionCount < 3) {
      throw new Error(
        `Production manifest requires at least three Phase 2 contributors for ${circuit.name}.`,
      );
    }
  }
  const trustedSetupTranscriptHash = existsSync(phase2TranscriptHashPath)
    ? readFileSync(phase2TranscriptHashPath, "utf8").trim().toLowerCase()
    : fallbackTrustedSetupTranscriptHash;
  const phase2TranscriptArtifact = phase2Transcript
    ? {
        ...artifactEntry({
          role: "metadata",
          path: phase2TranscriptPath,
          sha256: sha256File(phase2TranscriptPath),
          format: "json",
        }),
        path: unixRelativePath(artifactDir, phase2TranscriptPath),
      }
    : null;

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
      ...(phase2TranscriptArtifact ? [phase2TranscriptArtifact] : []),
    ],
    trustedSetup: {
      ceremony: ceremonyName,
      phase1TranscriptHash,
      phase2TranscriptHash: trustedSetupTranscriptHash,
      contributionCount:
        typeof phase2Transcript?.phase2?.contributionCount === "number"
          ? phase2Transcript.phase2.contributionCount
          : artifactProfile === "production"
            ? 0
            : 1,
      notes: defaultNotes,
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
