import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "bun:test";

import {
  GROTH16_ARTIFACT_MANIFEST_VERSION,
  buildGroth16VerifierKeyRegistryRecord,
  hashGroth16ArtifactManifest,
  loadGroth16ArtifactManifestFile,
  parseGroth16ArtifactManifest,
  validateGroth16ArtifactManifestConstraints,
  type Groth16ArtifactManifest,
} from "./groth16ArtifactManifestService";

const VERIFIER_KEY_HASH = "8".repeat(64);
const PROVING_KEY_HASH = "9".repeat(64);
const PROVER_ARTIFACT_HASH = "a".repeat(64);
const TRUSTED_SETUP_TRANSCRIPT_HASH = "b".repeat(64);

const createManifest = (
  overrides: Partial<Groth16ArtifactManifest> = {},
): Groth16ArtifactManifest => ({
  version: GROTH16_ARTIFACT_MANIFEST_VERSION,
  artifactKind: "vote",
  circuitId: "civicos-groth16-vote-circuit-v1",
  proofSystem: "groth16",
  protocol: "groth16",
  curve: "bn254",
  hashSuite: "poseidon-bn254-v1",
  publicInputSchemaVersion: "civicos-groth16-vote-public-inputs-v1",
  trustedSetupTranscriptHash: TRUSTED_SETUP_TRANSCRIPT_HASH,
  verifierKeyHash: VERIFIER_KEY_HASH,
  provingKeyHash: PROVING_KEY_HASH,
  wasmOrNativeArtifactHash: PROVER_ARTIFACT_HASH,
  circuitParameters: {
    credentialMerkleDepth: 32,
    maxOptions: 8,
  },
  artifacts: [
    {
      role: "verification_key",
      path: "vote.vkey.json",
      sha256: VERIFIER_KEY_HASH,
      format: "snarkjs-vkey-json",
    },
    {
      role: "proving_key",
      path: "vote.zkey",
      sha256: PROVING_KEY_HASH,
      format: "zkey",
    },
    {
      role: "witness_wasm",
      path: "vote.wasm",
      sha256: PROVER_ARTIFACT_HASH,
      format: "wasm",
    },
  ],
  ...overrides,
});

describe("groth16ArtifactManifestService", () => {
  it("parses a vote artifact manifest and builds a verifier-key registry record", () => {
    const parsed = parseGroth16ArtifactManifest(createManifest());

    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.manifestHash).toMatch(/^[0-9a-f]{64}$/);
      expect(parsed.registryRecord).toEqual(
        buildGroth16VerifierKeyRegistryRecord(
          parsed.manifest,
          parsed.manifestHash,
        ),
      );
      expect(parsed.registryRecord).toMatchObject({
        version: "civicos-groth16-verifier-key-registry-v1",
        artifactKind: "vote",
        proofSystem: "groth16",
        protocol: "groth16",
        curve: "bn254",
        circuitId: "civicos-groth16-vote-circuit-v1",
        verifierKeyHash: VERIFIER_KEY_HASH,
        publicInputSchemaVersion: "civicos-groth16-vote-public-inputs-v1",
        trustedSetupTranscriptHash: TRUSTED_SETUP_TRANSCRIPT_HASH,
      });
    }
  });

  it("rejects manifests where required artifact hashes are not pinned", () => {
    const parsed = parseGroth16ArtifactManifest(
      createManifest({
        artifacts: [
          {
            role: "verification_key",
            path: "vote.vkey.json",
            sha256: "1".repeat(64),
            format: "snarkjs-vkey-json",
          },
          {
            role: "proving_key",
            path: "vote.zkey",
            sha256: PROVING_KEY_HASH,
            format: "zkey",
          },
          {
            role: "witness_wasm",
            path: "vote.wasm",
            sha256: PROVER_ARTIFACT_HASH,
            format: "wasm",
          },
        ],
      }),
    );

    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.reason).toBe("MANIFEST_INVALID");
      expect(parsed.message).toContain("verification_key");
    }
  });

  it("loads a manifest file only when the pinned manifest hash matches", () => {
    const manifest = createManifest();
    const manifestHash = hashGroth16ArtifactManifest(manifest);
    const dir = mkdtempSync(join(tmpdir(), "civicos-groth16-manifest-"));
    const manifestPath = join(dir, "vote.manifest.json");
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    try {
      const loaded = loadGroth16ArtifactManifestFile({
        manifestPath,
        expectedArtifactKind: "vote",
        expectedManifestHash: manifestHash,
      });
      expect(loaded.ok).toBe(true);
      if (loaded.ok) {
        expect(loaded.manifestPath).toBe(manifestPath);
        expect(loaded.manifestHash).toBe(manifestHash);
      }

      const rejected = loadGroth16ArtifactManifestFile({
        manifestPath,
        expectedArtifactKind: "vote",
        expectedManifestHash: "0".repeat(64),
      });
      expect(rejected.ok).toBe(false);
      if (!rejected.ok) {
        expect(rejected.reason).toBe("MANIFEST_HASH_MISMATCH");
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("checks loaded manifests against verifier configuration constraints", () => {
    const manifest = createManifest();

    const accepted = validateGroth16ArtifactManifestConstraints(manifest, {
      artifactKind: "vote",
      circuitId: manifest.circuitId,
      verifierKeyHash: manifest.verifierKeyHash,
      publicInputSchemaVersion: manifest.publicInputSchemaVersion,
      trustedSetupTranscriptHash: manifest.trustedSetupTranscriptHash,
      circuitParameters: {
        credentialMerkleDepth: 32,
        maxOptions: 8,
      },
    });
    expect(accepted.ok).toBe(true);

    const rejected = validateGroth16ArtifactManifestConstraints(manifest, {
      circuitId: "other-circuit",
    });
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) {
      expect(rejected.reason).toBe("CONSTRAINT_MISMATCH");
    }

    const rejectedParameters = validateGroth16ArtifactManifestConstraints(
      manifest,
      {
        circuitParameters: {
          credentialMerkleDepth: 24,
        },
      },
    );
    expect(rejectedParameters.ok).toBe(false);
    if (!rejectedParameters.ok) {
      expect(rejectedParameters.reason).toBe("CONSTRAINT_MISMATCH");
      expect(rejectedParameters.message).toContain(
        "circuitParameters.credentialMerkleDepth=24",
      );
    }
  });
});
