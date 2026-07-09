import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { Groth16ArtifactManifest } from "./groth16ArtifactManifestService";
import type {
  Groth16VotePublicInputsDto,
  Groth16VoteVerifierEngine,
} from "./groth16ProofVerifierService";

const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const PUBLIC_FIELD_DOMAIN = "org.civicos.zkp:public-field:v1";
const SNARKJS_CLI_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../node_modules/.bin/snarkjs",
);

export const GROTH16_VOTE_PUBLIC_SIGNAL_ORDER = Object.freeze([
  "pollId",
  "pollPolicyHash",
  "credentialSchemaHash",
  "optionSetHash",
  "optionCount",
  "credentialRoot",
  "nullifier",
  "voteCommitment",
  "encryptedVoteCommitment",
] as const);

type Groth16VotePublicSignalName =
  (typeof GROTH16_VOTE_PUBLIC_SIGNAL_ORDER)[number];

const sha256Hex = (value: string | Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");

export const encodeGroth16PublicField = (
  name: string,
  value: string | number | bigint,
): string => {
  if (value === null || value === undefined) {
    throw new TypeError(`Groth16 public input ${name} is required.`);
  }

  const normalized =
    typeof value === "bigint" || typeof value === "number"
      ? value.toString()
      : value.trim();

  const lower = normalized.toLowerCase();
  if (HEX_64_PATTERN.test(lower)) {
    return (BigInt(`0x${lower}`) % BN254_SCALAR_FIELD).toString(10);
  }

  if (DECIMAL_PATTERN.test(normalized)) {
    return (BigInt(normalized) % BN254_SCALAR_FIELD).toString(10);
  }

  const digest = createHash("sha256");
  digest.update(PUBLIC_FIELD_DOMAIN, "utf8");
  digest.update("\0", "utf8");
  digest.update(name, "utf8");
  digest.update("\0", "utf8");
  digest.update(normalized, "utf8");
  return (BigInt(`0x${digest.digest("hex")}`) % BN254_SCALAR_FIELD).toString(
    10,
  );
};

export const encodeGroth16VotePublicSignals = (
  publicInputs: Groth16VotePublicInputsDto,
): string[] =>
  GROTH16_VOTE_PUBLIC_SIGNAL_ORDER.map((name) =>
    encodeGroth16PublicField(
      name,
      publicInputs[name as Groth16VotePublicSignalName],
    ),
  );

const resolveArtifactPath = (params: {
  manifestPath: string | null;
  artifactPath: string;
}): string => {
  if (isAbsolute(params.artifactPath)) {
    return params.artifactPath;
  }

  if (params.manifestPath) {
    const manifestPath = isAbsolute(params.manifestPath)
      ? params.manifestPath
      : resolve(process.cwd(), params.manifestPath);
    return resolve(dirname(manifestPath), params.artifactPath);
  }

  return resolve(process.cwd(), params.artifactPath);
};

const readVerificationKey = (params: {
  manifest: Groth16ArtifactManifest;
  manifestPath: string | null;
  expectedVerifierKeyHash: string;
}): unknown => {
  const verifierKeyArtifact = params.manifest.artifacts.find(
    (artifact) => artifact.role === "verification_key",
  );
  if (!verifierKeyArtifact) {
    throw new Error("Groth16 manifest does not contain a verification key.");
  }

  const verifierKeyPath = resolveArtifactPath({
    manifestPath: params.manifestPath,
    artifactPath: verifierKeyArtifact.path,
  });
  const verifierKeyBytes = readFileSync(verifierKeyPath);
  const verifierKeyHash = sha256Hex(verifierKeyBytes);
  if (
    verifierKeyHash !== verifierKeyArtifact.sha256 ||
    verifierKeyHash !== params.manifest.verifierKeyHash ||
    verifierKeyHash !== params.expectedVerifierKeyHash
  ) {
    throw new Error("Groth16 verification key hash does not match the manifest.");
  }

  return JSON.parse(verifierKeyBytes.toString("utf8"));
};

const verificationKeyCache = new Map<string, unknown>();

const getCachedVerificationKey = (params: {
  manifest: Groth16ArtifactManifest;
  manifestPath: string | null;
  manifestHash: string;
  expectedVerifierKeyHash: string;
}): unknown => {
  const cacheKey = `${params.manifestHash}:${params.expectedVerifierKeyHash}`;
  const cached = verificationKeyCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const verificationKey = readVerificationKey(params);
  verificationKeyCache.set(cacheKey, verificationKey);
  return verificationKey;
};

export const verifyGroth16ProofWithSnarkjs = async (input: {
  verificationKey: unknown;
  publicSignals: readonly string[];
  proof: unknown;
}): Promise<boolean> => {
  const tempDir = mkdtempSync(join(tmpdir(), "civicos-groth16-verify-"));
  const verificationKeyPath = join(tempDir, "verification_key.json");
  const publicSignalsPath = join(tempDir, "public.json");
  const proofPath = join(tempDir, "proof.json");

  try {
    writeFileSync(
      verificationKeyPath,
      `${JSON.stringify(input.verificationKey)}\n`,
    );
    writeFileSync(
      publicSignalsPath,
      `${JSON.stringify([...input.publicSignals])}\n`,
    );
    writeFileSync(proofPath, `${JSON.stringify(input.proof)}\n`);

    execFileSync(
      SNARKJS_CLI_PATH,
      ["groth16", "verify", verificationKeyPath, publicSignalsPath, proofPath],
      {
        stdio: "ignore",
        timeout: 30_000,
      },
    );
    return true;
  } catch {
    return false;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
};

export const verifyGroth16ProofFromManifestWithSnarkjs = async (input: {
  proof: unknown;
  publicSignals: readonly string[];
  artifactManifest: Groth16ArtifactManifest;
  artifactManifestPath: string | null;
  artifactManifestHash: string;
  verifierKeyHash: string;
}): Promise<boolean> => {
  const verificationKey = getCachedVerificationKey({
    manifest: input.artifactManifest,
    manifestPath: input.artifactManifestPath,
    manifestHash: input.artifactManifestHash,
    expectedVerifierKeyHash: input.verifierKeyHash,
  });

  return verifyGroth16ProofWithSnarkjs({
    verificationKey,
    publicSignals: input.publicSignals,
    proof: input.proof,
  });
};

export const verifyGroth16VoteProofWithSnarkjs: Groth16VoteVerifierEngine =
  async (input) => {
    const publicSignals = encodeGroth16VotePublicSignals(input.publicInputs);

    return verifyGroth16ProofFromManifestWithSnarkjs({
      artifactManifest: input.artifactManifest,
      artifactManifestPath: input.artifactManifestPath,
      artifactManifestHash: input.artifactManifestHash,
      verifierKeyHash: input.verifierKeyHash,
      publicSignals,
      proof: input.proof,
    });
  };

export default {
  GROTH16_VOTE_PUBLIC_SIGNAL_ORDER,
  encodeGroth16PublicField,
  encodeGroth16VotePublicSignals,
  verifyGroth16ProofFromManifestWithSnarkjs,
  verifyGroth16ProofWithSnarkjs,
  verifyGroth16VoteProofWithSnarkjs,
};
