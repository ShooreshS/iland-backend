import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  hashGroth16ArtifactManifest,
  type Groth16ArtifactManifest,
} from "./groth16ArtifactManifestService";
import {
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
  CIVIC_PRODUCTION_PROOF_PROTOCOL,
  CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
  CIVIC_PRODUCTION_VOTE_PRIVACY_MODE,
} from "./groth16ProofVerifierService";
import {
  CIVIC_TALLY_MAX_OPTIONS,
  CIVIC_TALLY_MAX_VOTES,
  CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
  CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  encodeGroth16TallyPublicSignals,
  getGroth16TallyVerifierConfig,
  hashGroth16TallyOptionCounts,
  hashGroth16TallyPublicInputs,
  isGroth16TallyVerifierConfigured,
  type Groth16TallyProofEnvelopeDto,
  type Groth16TallyVerifierConfig,
} from "./groth16TallyProofVerifierService";
import { encodeGroth16PublicField } from "./groth16SnarkjsVerifierEngine";
import {
  fieldElementToHex64,
  normalizeBn254FieldElement,
  poseidonHashFields,
} from "./poseidonBn254Service";
import pollEncryptedTallyService, {
  type DecryptedAcceptedEncryptedVote,
  type FinalEncryptedTallyBatchResult,
} from "./pollEncryptedTallyService";
import type { PollOptionRow, PollRow } from "../types/db";
import type { JsonValue } from "../types/json";

const SNARKJS_CLI_JS_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../node_modules/snarkjs/cli.js",
);
const NULLIFIER_LEAF_TAG = 1101;
const VOTE_COMMITMENT_LEAF_TAG = 1102;
const ENCRYPTED_VOTE_LEAF_TAG = 1103;
const ENCRYPTED_VOTE_TAG = 1001;
const OPTION_COUNTS_TAG = 1201;
const DEFAULT_PROVER_TIMEOUT_MS = 300_000;
const DEFAULT_PROVER_NODE_MAX_OLD_SPACE_MB = 2048;

type TallyWitnessInput = Record<string, string | string[] | string[][]>;

export type Groth16TallyProverRunProof = (input: {
  manifest: Groth16ArtifactManifest;
  manifestPath: string;
  witnessInput: TallyWitnessInput;
  expectedPublicSignals: readonly string[];
}) => Promise<{ proof: JsonValue; publicSignals: string[] }>;

export type Groth16TallyProverDependencies = Readonly<{
  config?: Groth16TallyVerifierConfig;
  encryptedTallyService?: Pick<
    typeof pollEncryptedTallyService,
    "getFinalizationBatch"
  >;
  runProof?: Groth16TallyProverRunProof;
}>;

export type GenerateGroth16TallyProofResult =
  | Readonly<{
      success: true;
      proof: Groth16TallyProofEnvelopeDto;
      countsByOptionId: Record<string, number>;
      acceptedVoteCount: number;
    }>
  | Readonly<{
      success: false;
      errorCode:
        | "POLL_NOT_PRODUCTION_ZKP"
        | "NO_ACCEPTED_AUDIT_VOTES"
        | "TALLY_BATCH_LIMIT_EXCEEDED"
        | "TALLY_OPTION_LIMIT_EXCEEDED"
        | "TALLY_PROVER_UNCONFIGURED"
        | "TALLY_WITNESS_INVALID"
        | "TALLY_PROOF_GENERATION_FAILED";
      message: string;
    }>;

export type Groth16TallyProverArtifactStatus = Readonly<{
  configured: boolean;
  provingKeyPath: string | null;
  provingKeyPresent: boolean;
  provingKeyBytes: number | null;
  witnessWasmPath: string | null;
  witnessWasmPresent: boolean;
  witnessWasmBytes: number | null;
  witnessGeneratorPath: string | null;
  witnessGeneratorPresent: boolean;
  snarkjsCliPath: string;
  snarkjsCliPresent: boolean;
  snarkjsCliVersion: string | null;
  snarkjsCliReady: boolean;
  commandTimeoutMs: number;
  nodeMaxOldSpaceMb: number;
  message: string | null;
}>;

const sha256Hex = (value: Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");

const parsePositiveIntegerEnv = (
  name: string,
  fallback: number,
): number => {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const proverCommandTimeoutMs = (): number =>
  parsePositiveIntegerEnv(
    "ZKP_GROTH16_TALLY_PROVER_TIMEOUT_MS",
    DEFAULT_PROVER_TIMEOUT_MS,
  );

const proverNodeMaxOldSpaceMb = (): number =>
  parsePositiveIntegerEnv(
    "ZKP_GROTH16_TALLY_PROVER_NODE_MAX_OLD_SPACE_MB",
    DEFAULT_PROVER_NODE_MAX_OLD_SPACE_MB,
  );

const outputToString = (value: unknown): string => {
  if (Buffer.isBuffer(value)) {
    return value.toString("utf8").trim();
  }
  return typeof value === "string" ? value.trim() : "";
};

const truncateOutput = (value: string, maxLength = 1_500): string =>
  value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;

const formatExecFailure = (label: string, error: unknown): string => {
  const parts = [`${label} failed`];
  if (typeof error === "object" && error !== null) {
    const record = error as Record<string, unknown>;
    const code = outputToString(record.code);
    const status =
      typeof record.status === "number" ? record.status.toString() : "";
    const signal = outputToString(record.signal);
    const stderr = truncateOutput(outputToString(record.stderr));
    const stdout = truncateOutput(outputToString(record.stdout));
    if (code) {
      parts.push(`code=${code}`);
    }
    if (status) {
      parts.push(`status=${status}`);
    }
    if (signal) {
      parts.push(`signal=${signal}`);
    }
    if (stderr) {
      parts.push(`stderr=${stderr}`);
    }
    if (stdout) {
      parts.push(`stdout=${stdout}`);
    }
  }

  if (error instanceof Error) {
    parts.push(`message=${truncateOutput(error.message)}`);
  }

  return parts.join("; ");
};

const execNodeOrThrow = (
  label: string,
  args: string[],
  timeoutMs = proverCommandTimeoutMs(),
): string => {
  try {
    return execFileSync("node", args, {
      encoding: "utf8",
      stdio: "pipe",
      timeout: timeoutMs,
    });
  } catch (error) {
    throw new Error(formatExecFailure(label, error));
  }
};

const getSnarkjsCliVersion = (): string | null => {
  if (!existsSync(SNARKJS_CLI_JS_PATH)) {
    return null;
  }

  const parseVersion = (output: string): string | null =>
    output
      .split("\n")
      .map((line) => line.trim())
      .find((line) => /^snarkjs@/u.test(line)) ?? null;

  try {
    return parseVersion(
      execFileSync("node", [SNARKJS_CLI_JS_PATH], {
        encoding: "utf8",
        stdio: "pipe",
        timeout: 10_000,
      }),
    );
  } catch (error) {
    if (typeof error === "object" && error !== null) {
      const record = error as Record<string, unknown>;
      return parseVersion(
        [outputToString(record.stdout), outputToString(record.stderr)]
          .filter(Boolean)
          .join("\n"),
      );
    }
    return null;
  }
};

const orderedActiveOptions = (
  options: readonly PollOptionRow[],
): PollOptionRow[] =>
  [...options]
    .filter((option) => option.is_active !== false)
    .sort((left, right) => left.display_order - right.display_order);

const fieldDecimal = (value: string | number | bigint): string =>
  normalizeBn254FieldElement(value).toString(10);

const resolveArtifactPath = (params: {
  manifestPath: string;
  artifactPath: string;
}): string =>
  isAbsolute(params.artifactPath)
    ? params.artifactPath
    : resolve(dirname(params.manifestPath), params.artifactPath);

const getArtifactPath = (params: {
  manifest: Groth16ArtifactManifest;
  manifestPath: string;
  role: "proving_key" | "witness_wasm";
  expectedHash: string;
}): string => {
  const artifact = params.manifest.artifacts.find(
    (entry) => entry.role === params.role,
  );
  if (!artifact) {
    throw new Error(`Groth16 tally manifest is missing ${params.role}.`);
  }
  if (artifact.sha256 !== params.expectedHash) {
    throw new Error(`Groth16 tally ${params.role} hash is not pinned.`);
  }
  const artifactPath = resolveArtifactPath({
    manifestPath: params.manifestPath,
    artifactPath: artifact.path,
  });
  const bytes = readFileSync(artifactPath);
  if (sha256Hex(bytes) !== artifact.sha256) {
    throw new Error(`Groth16 tally ${params.role} file hash mismatch.`);
  }
  return artifactPath;
};

const resolveManifestArtifactPath = (params: {
  manifest: Groth16ArtifactManifest;
  manifestPath: string;
  role: "proving_key" | "witness_wasm";
}): string | null => {
  const artifact = params.manifest.artifacts.find(
    (entry) => entry.role === params.role,
  );
  if (!artifact) {
    return null;
  }

  return resolveArtifactPath({
    manifestPath: params.manifestPath,
    artifactPath: artifact.path,
  });
};

const fileSizeOrNull = (path: string | null): number | null => {
  if (!path || !existsSync(path)) {
    return null;
  }
  return statSync(path).size;
};

const artifactPathCache = new Map<
  string,
  Readonly<{
    provingKeyPath: string;
    wasmPath: string;
    witnessGeneratorPath: string;
  }>
>();

const getProverArtifactPaths = (params: {
  manifest: Groth16ArtifactManifest;
  manifestPath: string;
  manifestHash: string;
}): Readonly<{
  provingKeyPath: string;
  wasmPath: string;
  witnessGeneratorPath: string;
}> => {
  const cacheKey = `${params.manifestHash}:${params.manifest.provingKeyHash}:${params.manifest.wasmOrNativeArtifactHash}`;
  const cached = artifactPathCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const provingKeyPath = getArtifactPath({
    manifest: params.manifest,
    manifestPath: params.manifestPath,
    role: "proving_key",
    expectedHash: params.manifest.provingKeyHash,
  });
  const wasmPath = getArtifactPath({
    manifest: params.manifest,
    manifestPath: params.manifestPath,
    role: "witness_wasm",
    expectedHash: params.manifest.wasmOrNativeArtifactHash,
  });
  const witnessGeneratorPath = resolve(dirname(wasmPath), "generate_witness.js");
  if (!existsSync(witnessGeneratorPath)) {
    throw new Error(
      `Groth16 tally witness generator is missing: ${witnessGeneratorPath}`,
    );
  }

  const resolved = Object.freeze({
    provingKeyPath,
    wasmPath,
    witnessGeneratorPath,
  });
  artifactPathCache.set(cacheKey, resolved);
  return resolved;
};

const defaultRunProof: Groth16TallyProverRunProof = async (input) => {
  const { provingKeyPath, wasmPath, witnessGeneratorPath } =
    getProverArtifactPaths({
      manifest: input.manifest,
      manifestPath: input.manifestPath,
      manifestHash: hashGroth16ArtifactManifest(input.manifest),
    });
  const tempDir = mkdtempSync(join(tmpdir(), "civicos-tally-prove-"));
  const inputPath = join(tempDir, "input.json");
  const witnessPath = join(tempDir, "witness.wtns");
  const proofPath = join(tempDir, "proof.json");
  const publicPath = join(tempDir, "public.json");

  try {
    writeFileSync(inputPath, `${JSON.stringify(input.witnessInput)}\n`);
    execNodeOrThrow(
      "Groth16 tally witness generation",
      [witnessGeneratorPath, wasmPath, inputPath, witnessPath],
    );
    execNodeOrThrow(
      "Groth16 tally proof generation",
      [
        `--max-old-space-size=${proverNodeMaxOldSpaceMb()}`,
        SNARKJS_CLI_JS_PATH,
        "groth16",
        "prove",
        provingKeyPath,
        witnessPath,
        proofPath,
        publicPath,
      ],
    );

    return {
      proof: JSON.parse(readFileSync(proofPath, "utf8")) as JsonValue,
      publicSignals: JSON.parse(readFileSync(publicPath, "utf8")) as string[],
    };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
};

const deriveFixedPoseidonRoot = async (
  leaves: readonly string[],
): Promise<string> => {
  if (leaves.length !== CIVIC_TALLY_MAX_VOTES) {
    throw new Error(
      `Fixed tally audit tree requires ${CIVIC_TALLY_MAX_VOTES} leaves.`,
    );
  }

  let level = leaves.map(fieldDecimal);
  while (level.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < level.length; index += 2) {
      next.push(await poseidonHashFields([level[index], level[index + 1]]));
    }
    level = next;
  }
  return level[0];
};

const optionSelectionRow = (optionIndex: number): string[] =>
  Array.from({ length: CIVIC_TALLY_MAX_OPTIONS }, (_, index) =>
    index === optionIndex ? "1" : "0",
  );

const buildWitness = async (input: {
  poll: PollRow;
  options: readonly PollOptionRow[];
  batch: Extract<FinalEncryptedTallyBatchResult, { success: true }>;
}): Promise<{
  witnessInput: TallyWitnessInput;
  publicInputs: Groth16TallyProofEnvelopeDto["publicInputs"];
}> => {
  const options = orderedActiveOptions(input.options);
  const votes = input.batch.votes;
  const optionCounts = Array.from(
    { length: CIVIC_TALLY_MAX_OPTIONS },
    (_, optionIndex) =>
      votes.filter((vote) => vote.optionIndex === optionIndex).length,
  );
  const paddedVotes: (DecryptedAcceptedEncryptedVote | null)[] = Array.from(
    { length: CIVIC_TALLY_MAX_VOTES },
    (_, index) => votes[index] ?? null,
  );
  const pollPolicyHash = input.poll.poll_policy_hash || "";
  const credentialSchemaHash = input.poll.credential_schema_hash || "";
  const optionSetHash = input.poll.option_set_hash || "";
  const circuitPollId = encodeGroth16PublicField("pollId", input.poll.id);
  const circuitPollPolicyHash = encodeGroth16PublicField(
    "pollPolicyHash",
    pollPolicyHash,
  );
  const circuitCredentialSchemaHash = encodeGroth16PublicField(
    "credentialSchemaHash",
    credentialSchemaHash,
  );
  const circuitOptionSetHash = encodeGroth16PublicField(
    "optionSetHash",
    optionSetHash,
  );

  const encryptedVoteCommitments: string[] = [];
  const voteCommitments: string[] = [];
  const nullifierLeaves: string[] = [];
  const voteCommitmentLeaves: string[] = [];
  const encryptedVoteLeaves: string[] = [];
  for (const vote of paddedVotes) {
    if (!vote) {
      encryptedVoteCommitments.push("0");
      voteCommitments.push("0");
      nullifierLeaves.push("0");
      voteCommitmentLeaves.push("0");
      encryptedVoteLeaves.push("0");
      continue;
    }

    const encryptedVoteCommitment = await poseidonHashFields([
      ENCRYPTED_VOTE_TAG,
      vote.optionIndex,
      vote.encryptedVoteRandomness,
      circuitOptionSetHash,
    ]);
    const encryptedVoteCommitmentHex = fieldElementToHex64(
      encryptedVoteCommitment,
    );
    if (encryptedVoteCommitmentHex !== vote.encryptedVoteCommitment) {
      throw new Error("Encrypted vote opening does not match its commitment.");
    }
    const voteCommitment = await poseidonHashFields([
      vote.nullifier,
      encryptedVoteCommitment,
      circuitOptionSetHash,
      vote.voteRandomness,
    ]);
    const voteCommitmentHex = fieldElementToHex64(voteCommitment);
    if (voteCommitmentHex !== vote.voteCommitment) {
      throw new Error("Encrypted vote opening does not match its vote commitment.");
    }

    encryptedVoteCommitments.push(encryptedVoteCommitment);
    voteCommitments.push(voteCommitment);
    nullifierLeaves.push(
      await poseidonHashFields([NULLIFIER_LEAF_TAG, vote.nullifier]),
    );
    voteCommitmentLeaves.push(
      await poseidonHashFields([VOTE_COMMITMENT_LEAF_TAG, voteCommitment]),
    );
    encryptedVoteLeaves.push(
      await poseidonHashFields([
        ENCRYPTED_VOTE_LEAF_TAG,
        encryptedVoteCommitment,
      ]),
    );
  }

  const nullifierRoot = await deriveFixedPoseidonRoot(nullifierLeaves);
  const voteCommitmentRoot = await deriveFixedPoseidonRoot(voteCommitmentLeaves);
  const encryptedVoteRoot = await deriveFixedPoseidonRoot(encryptedVoteLeaves);
  const optionCountsHash = await poseidonHashFields([
    OPTION_COUNTS_TAG,
    ...optionCounts,
  ]);
  const optionResults = options.map((option, optionIndex) => ({
    optionId: option.id,
    count: optionCounts[optionIndex] ?? 0,
  }));
  const publicInputs: Groth16TallyProofEnvelopeDto["publicInputs"] = {
    version: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    pollId: input.poll.id,
    pollPolicyHash,
    credentialSchemaHash,
    optionSetHash,
    optionCount: options.length,
    nullifierRoot: fieldElementToHex64(nullifierRoot),
    voteCommitmentRoot: fieldElementToHex64(voteCommitmentRoot),
    encryptedVoteRoot: fieldElementToHex64(encryptedVoteRoot),
    acceptedVoteCount: votes.length,
    optionResults,
    optionCountsHash: await hashGroth16TallyOptionCounts(optionResults),
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: "",
    verifierKeyHash: "",
    publicInputSchemaVersion: "",
  };

  return {
    witnessInput: {
      pollId: circuitPollId,
      pollPolicyHash: circuitPollPolicyHash,
      credentialSchemaHash: circuitCredentialSchemaHash,
      optionSetHash: circuitOptionSetHash,
      optionCount: String(options.length),
      isActive: paddedVotes.map((vote) => (vote ? "1" : "0")),
      nullifiers: paddedVotes.map((vote) =>
        vote ? fieldDecimal(vote.nullifier) : "0",
      ),
      encryptedVoteCommitments,
      encryptedVoteRandomness: paddedVotes.map((vote) =>
        vote ? fieldDecimal(vote.encryptedVoteRandomness) : "0",
      ),
      voteRandomness: paddedVotes.map((vote) =>
        vote ? fieldDecimal(vote.voteRandomness) : "0",
      ),
      optionSelections: paddedVotes.map((vote) =>
        vote ? optionSelectionRow(vote.optionIndex) : optionSelectionRow(-1),
      ),
      optionCounts: optionCounts.map(String),
      nullifierRoot,
      voteCommitmentRoot,
      encryptedVoteRoot,
      acceptedVoteCount: String(votes.length),
      optionCountsHash,
    },
    publicInputs,
  };
};

const failure = (
  errorCode: Extract<GenerateGroth16TallyProofResult, { success: false }>["errorCode"],
  message: string,
): GenerateGroth16TallyProofResult => ({
  success: false,
  errorCode,
  message,
});

export const createGroth16TallyProverService = (
  dependencies: Groth16TallyProverDependencies = {},
) => {
  const encryptedTallyService =
    dependencies.encryptedTallyService ?? pollEncryptedTallyService;
  const runProof = dependencies.runProof ?? defaultRunProof;

  return {
    async generateProofForPoll(input: {
      poll: PollRow;
      options: readonly PollOptionRow[];
    }): Promise<GenerateGroth16TallyProofResult> {
      if (input.poll.vote_privacy_mode !== CIVIC_PRODUCTION_VOTE_PRIVACY_MODE) {
        return failure(
          "POLL_NOT_PRODUCTION_ZKP",
          "Only production ZKP polls can generate Groth16 tally proofs.",
        );
      }

      const options = orderedActiveOptions(input.options);
      if (
        options.length < 1 ||
        options.length > CIVIC_TALLY_MAX_OPTIONS
      ) {
        return failure(
          "TALLY_OPTION_LIMIT_EXCEEDED",
          `Groth16 tally proofs require 1-${CIVIC_TALLY_MAX_OPTIONS} active options.`,
        );
      }

      const config = dependencies.config ?? getGroth16TallyVerifierConfig();
      if (
        !isGroth16TallyVerifierConfigured(config) ||
        !config.tallyArtifactManifest ||
        !config.tallyArtifactManifestPath ||
        !config.tallyVerifierKeyHash ||
        !config.tallyCircuitId ||
        !config.tallyPublicInputSchemaVersion
      ) {
        return failure(
          "TALLY_PROVER_UNCONFIGURED",
          "Groth16 tally prover artifacts are not fully configured.",
        );
      }

      const batch = await encryptedTallyService.getFinalizationBatch({
        poll: input.poll,
        options,
      });
      if (!batch.success) {
        return failure("TALLY_WITNESS_INVALID", batch.message);
      }
      if (batch.totalVotes <= 0) {
        return failure(
          "NO_ACCEPTED_AUDIT_VOTES",
          "This poll has no accepted proof-backed votes to tally.",
        );
      }
      if (batch.totalVotes > CIVIC_TALLY_MAX_VOTES) {
        return failure(
          "TALLY_BATCH_LIMIT_EXCEEDED",
          `The v1 tally prover supports at most ${CIVIC_TALLY_MAX_VOTES} accepted votes.`,
        );
      }

      let witness: Awaited<ReturnType<typeof buildWitness>>;
      try {
        witness = await buildWitness({
          poll: input.poll,
          options,
          batch,
        });
      } catch (error) {
        return failure(
          "TALLY_WITNESS_INVALID",
          error instanceof Error
            ? error.message
            : "Groth16 tally witness could not be built.",
        );
      }

      const publicInputs = {
        ...witness.publicInputs,
        circuitId: config.tallyCircuitId,
        verifierKeyHash: config.tallyVerifierKeyHash,
        publicInputSchemaVersion: config.tallyPublicInputSchemaVersion,
      };
      const expectedPublicSignals = encodeGroth16TallyPublicSignals(publicInputs);

      let proof: JsonValue;
      let publicSignals: string[];
      try {
        const result = await runProof({
          manifest: config.tallyArtifactManifest,
          manifestPath: config.tallyArtifactManifestPath,
          witnessInput: witness.witnessInput,
          expectedPublicSignals,
        });
        proof = result.proof;
        publicSignals = result.publicSignals;
      } catch (error) {
        return failure(
          "TALLY_PROOF_GENERATION_FAILED",
          error instanceof Error
            ? error.message
            : "Groth16 tally proof generation failed.",
        );
      }

      if (JSON.stringify(publicSignals) !== JSON.stringify(expectedPublicSignals)) {
        return failure(
          "TALLY_PROOF_GENERATION_FAILED",
          "Groth16 tally prover returned unexpected public signals.",
        );
      }

      const envelope: Groth16TallyProofEnvelopeDto = {
        version: CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
        protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
        proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
        status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
        hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
        circuitId: config.tallyCircuitId,
        verifierKeyHash: config.tallyVerifierKeyHash,
        publicInputSchemaVersion: config.tallyPublicInputSchemaVersion,
        proof,
        publicInputs,
        publicInputsHash: hashGroth16TallyPublicInputs(publicInputs),
      };

      return {
        success: true,
        proof: envelope,
        countsByOptionId: batch.countsByOptionId,
        acceptedVoteCount: batch.totalVotes,
      };
    },
  };
};

export const groth16TallyProverService = createGroth16TallyProverService();

export const getGroth16TallyProverArtifactStatus = (
  config: Groth16TallyVerifierConfig = getGroth16TallyVerifierConfig(),
): Groth16TallyProverArtifactStatus => {
  const snarkjsCliPresent = existsSync(SNARKJS_CLI_JS_PATH);
  const snarkjsCliVersion = getSnarkjsCliVersion();
  const snarkjsCliReady = Boolean(snarkjsCliPresent && snarkjsCliVersion);
  const commandTimeoutMs = proverCommandTimeoutMs();
  const nodeMaxOldSpaceMb = proverNodeMaxOldSpaceMb();

  if (
    !isGroth16TallyVerifierConfigured(config) ||
    !config.tallyArtifactManifest ||
    !config.tallyArtifactManifestPath
  ) {
    return {
      configured: false,
      provingKeyPath: null,
      provingKeyPresent: false,
      provingKeyBytes: null,
      witnessWasmPath: null,
      witnessWasmPresent: false,
      witnessWasmBytes: null,
      witnessGeneratorPath: null,
      witnessGeneratorPresent: false,
      snarkjsCliPath: SNARKJS_CLI_JS_PATH,
      snarkjsCliPresent,
      snarkjsCliVersion,
      snarkjsCliReady,
      commandTimeoutMs,
      nodeMaxOldSpaceMb,
      message: "Groth16 tally verifier/artifact manifest is not configured.",
    };
  }

  const provingKeyPath = resolveManifestArtifactPath({
    manifest: config.tallyArtifactManifest,
    manifestPath: config.tallyArtifactManifestPath,
    role: "proving_key",
  });
  const witnessWasmPath = resolveManifestArtifactPath({
    manifest: config.tallyArtifactManifest,
    manifestPath: config.tallyArtifactManifestPath,
    role: "witness_wasm",
  });
  const witnessGeneratorPath = witnessWasmPath
    ? resolve(dirname(witnessWasmPath), "generate_witness.js")
    : null;
  const provingKeyBytes = fileSizeOrNull(provingKeyPath);
  const witnessWasmBytes = fileSizeOrNull(witnessWasmPath);
  const witnessGeneratorPresent = Boolean(
    witnessGeneratorPath && existsSync(witnessGeneratorPath),
  );
  const configured = Boolean(
    provingKeyBytes &&
      witnessWasmBytes &&
      witnessGeneratorPresent &&
      snarkjsCliReady,
  );

  return {
    configured,
    provingKeyPath,
    provingKeyPresent: Boolean(provingKeyBytes),
    provingKeyBytes,
    witnessWasmPath,
    witnessWasmPresent: Boolean(witnessWasmBytes),
    witnessWasmBytes,
    witnessGeneratorPath,
    witnessGeneratorPresent,
    snarkjsCliPath: SNARKJS_CLI_JS_PATH,
    snarkjsCliPresent,
    snarkjsCliVersion,
    snarkjsCliReady,
    commandTimeoutMs,
    nodeMaxOldSpaceMb,
    message: configured
      ? null
      : snarkjsCliReady
        ? "Groth16 tally prover zkey/WASM artifacts are not present in this runtime."
        : "Groth16 tally prover snarkjs runtime is not executable in this runtime.",
  };
};

export default groth16TallyProverService;
