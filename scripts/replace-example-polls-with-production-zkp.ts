#!/usr/bin/env bun
import {
  createCipheriv,
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import {
  dirname,
  isAbsolute,
  join,
  resolve,
} from "node:path";
import { fileURLToPath } from "node:url";

import type {
  PollOptionRow,
  PollRow,
  PollEncryptionKeyRow,
  UserRow,
} from "../src/types/db";
import type { JsonValue } from "../src/types/json";

type Groth16ArtifactManifest = {
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
  trustedSetupTranscriptHash: string;
  artifacts: Array<{
    role: string;
    path: string;
  }>;
};

type ReplacementMode = "dry-run" | "apply";
type FinalPollStatus = "active" | "closed";

type GeneratedVoteMaterial = {
  optionId: string;
  optionIndex: number;
  optionIndexBits: string[];
  identitySecret: string;
  identityKeyHash: string;
  claimsHash: string;
  encryptedVoteRandomness: string;
  voteRandomness: string;
  nullifier: string;
  voteCommitment: string;
  encryptedVoteHash: string;
  encryptedVoteCommitment: string;
  proofEnvelopeHash: string;
  acceptedAt: string;
};

type ReplacementSummary = {
  sourcePollId: string;
  replacementPollId: string;
  title: string;
  acceptedVoteCount: number;
  tallyProofHash: string;
  resultHash: string;
  finalStatus: FinalPollStatus;
};

const backendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const circuitRoot = resolve(backendRoot, "zkp/circuits");
const circuitBuildDir = resolve(circuitRoot, "build");
const snarkjsPath = resolve(backendRoot, "node_modules/.bin/snarkjs");
const voteManifestPath = resolve(
  backendRoot,
  "src/zkp-artifacts/groth16-vote/credential_commitment_vote.manifest.json",
);
const tallyManifestPath = resolve(
  backendRoot,
  "src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest.json",
);

const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;
const MAX_TALLY_VOTES = 64;
const MAX_ZKP_OPTIONS = 8;
const DEFAULT_SAMPLE_VOTES_PER_POLL = 3;

const usage = () => `
Usage:
  bun scripts/replace-example-polls-with-production-zkp.ts [--dry-run|--apply] [--delete-originals]

Modes:
  --dry-run            Inspect existing source polls and print what would be replaced. Default.
  --apply              Create replacement production ZKP polls, verified votes, and verified tally proofs.
  --delete-originals   Delete source polls after every replacement succeeds. Requires --apply and
                       CIVICOS_ZKP_REPLACE_CONFIRM_DELETE=true.

Useful env:
  SUPABASE_URL
  SUPABASE_SERVICE_ROLE_KEY
  CIVICOS_ZKP_REPLACE_VOTES_PER_POLL=3
  CIVICOS_ZKP_REPLACE_FINAL_STATUS=closed
  CIVICOS_ZKP_REPLACE_INCLUDE_PRODUCTION=false
  CIVICOS_ALLOW_ZKP_TEST_DATA_WRITES=true
  CIVICOS_ZKP_REPLACE_CONFIRM_DELETE=true
`;

const parseArgs = (): {
  mode: ReplacementMode;
  deleteOriginals: boolean;
} => {
  let mode: ReplacementMode = "dry-run";
  let deleteOriginals = false;

  for (const arg of process.argv.slice(2)) {
    if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (arg === "--dry-run") {
      mode = "dry-run";
      continue;
    }
    if (arg === "--apply") {
      mode = "apply";
      continue;
    }
    if (arg === "--delete-originals") {
      deleteOriginals = true;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return { mode, deleteOriginals };
};

const toBoolean = (value: string | undefined): boolean => {
  const normalized = value?.trim().toLowerCase() ?? "";
  return normalized === "1" || normalized === "true" || normalized === "yes";
};

const positiveIntEnv = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer.`);
  }
  return parsed;
};

const finalPollStatusEnv = (): FinalPollStatus => {
  const raw = process.env.CIVICOS_ZKP_REPLACE_FINAL_STATUS?.trim() || "closed";
  if (raw !== "active" && raw !== "closed") {
    throw new Error("CIVICOS_ZKP_REPLACE_FINAL_STATUS must be active or closed.");
  }
  return raw;
};

const readJson = <T>(path: string): T =>
  JSON.parse(readFileSync(path, "utf8")) as T;

const readManifestHash = (path: string): string =>
  readFileSync(path.replace(/\.json$/, "-hash.txt"), "utf8")
    .trim()
    .toLowerCase();

const writeJson = (path: string, value: unknown): void => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

const sha256Hex = (value: string | Buffer): string =>
  createHash("sha256").update(value).digest("hex");

const canonicalizeJson = (value: unknown): string => {
  const normalize = (entry: unknown): JsonValue => {
    if (entry === null) {
      return null;
    }
    if (
      typeof entry === "string" ||
      typeof entry === "boolean" ||
      typeof entry === "number"
    ) {
      return entry;
    }
    if (Array.isArray(entry)) {
      return entry.map(normalize);
    }
    if (typeof entry === "object") {
      const record = entry as Record<string, unknown>;
      return Object.keys(record)
        .sort()
        .reduce<Record<string, JsonValue>>((acc, key) => {
          if (record[key] !== undefined) {
            acc[key] = normalize(record[key]);
          }
          return acc;
        }, {});
    }
    throw new Error("Value is not canonical JSON compatible.");
  };

  return JSON.stringify(normalize(value));
};

const fieldElementToHex64 = (value: string | bigint): string => {
  const bigint =
    typeof value === "bigint"
      ? value
      : HEX_64_PATTERN.test(value)
        ? BigInt(`0x${value}`)
        : BigInt(value);
  return (bigint % BN254_SCALAR_FIELD).toString(16).padStart(64, "0");
};

const fieldElementToDecimal = (value: string | bigint): string =>
  (typeof value === "bigint"
    ? value
    : HEX_64_PATTERN.test(value)
      ? BigInt(`0x${value}`)
      : BigInt(value)
  )
    .valueOf()
    .toString(10);

const hexFieldToDecimal = (value: string): string =>
  (BigInt(`0x${value}`) % BN254_SCALAR_FIELD).toString(10);

const base64url = (value: Buffer): string =>
  value
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const artifactPath = (
  manifestPath: string,
  manifest: Groth16ArtifactManifest,
  role: string,
): string => {
  const artifact = manifest.artifacts.find((entry) => entry.role === role);
  if (!artifact) {
    throw new Error(`Manifest ${manifestPath} is missing ${role}.`);
  }
  return isAbsolute(artifact.path)
    ? artifact.path
    : resolve(dirname(manifestPath), artifact.path);
};

const configureScriptEnv = (): {
  voteManifest: Groth16ArtifactManifest;
  tallyManifest: Groth16ArtifactManifest;
} => {
  process.env.NODE_ENV ||= "development";
  process.env.ILAND_ENV_VALIDATION_SCOPE ||= "supabase-admin-script";
  process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS ||= "true";
  process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED ||= "false";

  const voteManifest =
    readJson<Groth16ArtifactManifest>(voteManifestPath);
  const tallyManifest =
    readJson<Groth16ArtifactManifest>(tallyManifestPath);

  if (!toBoolean(process.env.CIVICOS_ZKP_REPLACE_RESPECT_ENV_ARTIFACTS)) {
    process.env.ZKP_GROTH16_VOTE_VERIFIER_ENABLED = "true";
    process.env.ZKP_GROTH16_VOTE_CIRCUIT_ID = voteManifest.circuitId;
    process.env.ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH =
      voteManifest.verifierKeyHash;
    process.env.ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION =
      voteManifest.publicInputSchemaVersion;
    process.env.ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH =
      voteManifest.trustedSetupTranscriptHash;
    process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH =
      "src/zkp-artifacts/groth16-vote/credential_commitment_vote.manifest.json";
    process.env.ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH =
      readManifestHash(voteManifestPath);

    process.env.ZKP_GROTH16_TALLY_VERIFIER_ENABLED = "true";
    process.env.ZKP_GROTH16_TALLY_CIRCUIT_ID = tallyManifest.circuitId;
    process.env.ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH =
      tallyManifest.verifierKeyHash;
    process.env.ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION =
      tallyManifest.publicInputSchemaVersion;
    process.env.ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH =
      tallyManifest.trustedSetupTranscriptHash;
    process.env.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH =
      "src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest.json";
    process.env.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH =
      readManifestHash(tallyManifestPath);
  }

  return { voteManifest, tallyManifest };
};

const assertCircuitArtifactsExist = (
  voteManifest: Groth16ArtifactManifest,
  tallyManifest: Groth16ArtifactManifest,
): void => {
  const required = [
    snarkjsPath,
    artifactPath(voteManifestPath, voteManifest, "proving_key"),
    artifactPath(voteManifestPath, voteManifest, "witness_wasm"),
    artifactPath(tallyManifestPath, tallyManifest, "proving_key"),
    artifactPath(tallyManifestPath, tallyManifest, "witness_wasm"),
    resolve(
      circuitBuildDir,
      "credential_commitment_vote_js/generate_witness.js",
    ),
    resolve(circuitBuildDir, "encrypted_choice_tally_js/generate_witness.js"),
  ];

  const missing = required.filter((path) => !existsSync(path));
  if (missing.length > 0) {
    throw new Error(
      `ZKP proving artifacts are missing:\n${missing
        .map((path) => `  - ${path}`)
        .join("\n")}`,
    );
  }
};

const runGroth16Proof = (input: {
  circuitName: "credential_commitment_vote" | "encrypted_choice_tally";
  manifest: Groth16ArtifactManifest;
  manifestPath: string;
  witnessInput: Record<string, unknown>;
}): { proof: JsonValue; publicSignals: string[] } => {
  const tempDir = mkdtempSync(join(tmpdir(), `civicos-${input.circuitName}-`));
  try {
    const inputPath = join(tempDir, "input.json");
    const witnessPath = join(tempDir, "witness.wtns");
    const proofPath = join(tempDir, "proof.json");
    const publicPath = join(tempDir, "public.json");
    const witnessGenerator = resolve(
      circuitBuildDir,
      `${input.circuitName}_js/generate_witness.js`,
    );
    const wasmPath = artifactPath(
      input.manifestPath,
      input.manifest,
      "witness_wasm",
    );
    const provingKeyPath = artifactPath(
      input.manifestPath,
      input.manifest,
      "proving_key",
    );

    writeJson(inputPath, input.witnessInput);
    execFileSync("node", [witnessGenerator, wasmPath, inputPath, witnessPath], {
      cwd: circuitRoot,
      stdio: "pipe",
    });
    execFileSync(
      snarkjsPath,
      ["groth16", "prove", provingKeyPath, witnessPath, proofPath, publicPath],
      {
        cwd: backendRoot,
        stdio: "pipe",
      },
    );

    return {
      proof: readJson<JsonValue>(proofPath),
      publicSignals: readJson<string[]>(publicPath),
    };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
};

const optionBits = (optionIndex: number): string[] => [
  String(optionIndex & 1),
  String((optionIndex >> 1) & 1),
  String((optionIndex >> 2) & 1),
];

const normalizeActiveOptions = (options: PollOptionRow[]): PollOptionRow[] =>
  [...options]
    .filter((option) => option.is_active)
    .sort((left, right) => {
      if (left.display_order !== right.display_order) {
        return left.display_order - right.display_order;
      }
      return left.id.localeCompare(right.id);
    });

const sourcePollAllowed = (poll: PollRow): boolean => {
  if (toBoolean(process.env.CIVICOS_ZKP_REPLACE_INCLUDE_PRODUCTION)) {
    return true;
  }
  return poll.vote_privacy_mode !== "zk_secret_ballot_v1";
};

const pollInputFromSource = (
  source: PollRow,
  options: PollOptionRow[],
  pollEncryptionKeyId: string,
) => ({
  title: source.title,
  description: source.description,
  status: "active" as const,
  jurisdictionType: source.jurisdiction_type,
  jurisdictionCountryCode: source.jurisdiction_country_code,
  jurisdictionAreaIds: source.jurisdiction_area_ids || [],
  jurisdictionLandIds: source.jurisdiction_land_ids || [],
  eligibilityRule: {
    requiresVerifiedIdentity: true,
    allowedDocumentCountryCodes:
      source.allowed_document_country_codes?.length
        ? source.allowed_document_country_codes
        : undefined,
    allowedHomeAreaIds:
      source.allowed_home_area_ids?.length
        ? source.allowed_home_area_ids
        : undefined,
    allowedLandIds:
      source.allowed_land_ids?.length ? source.allowed_land_ids : undefined,
    minimumAge: source.minimum_age,
  },
  votePrivacyMode: "zk_secret_ballot_v1" as const,
  pollEncryptionKeyId,
  options: normalizeActiveOptions(options).map((option) => ({
    label: option.label,
    description: option.description,
    color: option.color,
  })),
});

const selectProfileForPoll = (poll: PollRow) => ({
  documentCountryCode:
    poll.allowed_document_country_codes?.[0] ||
    poll.jurisdiction_country_code ||
    "IR",
  homeCountryCode:
    poll.allowed_document_country_codes?.[0] ||
    poll.jurisdiction_country_code ||
    "IR",
  homeAreaId:
    poll.allowed_home_area_ids?.[0] || poll.jurisdiction_area_ids?.[0] || null,
  selectedLandId:
    poll.allowed_land_ids?.[0] || poll.jurisdiction_land_ids?.[0] || null,
});

const assertHex64 = (name: string, value: string | null | undefined): string => {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (!HEX_64_PATTERN.test(normalized)) {
    throw new Error(`${name} is not a 32-byte lowercase hex value.`);
  }
  return normalized;
};

const ensureSyntheticVerifiedUser = async (input: {
  supabase: ReturnType<
    typeof import("../src/db/supabaseClient").requireSupabaseAdminClient
  >;
  key: string;
  profile: ReturnType<typeof selectProfileForPoll>;
}): Promise<{
  user: UserRow;
  verifiedIdentity: {
    id: string;
    canonical_identity_key: string;
  };
}> => {
  const canonicalIdentityKey = sha256Hex(
    `civicos-zkp-replacement|canonical-identity|${input.key}`,
  );
  const { data: existingIdentity, error: existingIdentityError } =
    await input.supabase
      .from("verified_identities")
      .select(
        "id,user_id,canonical_identity_key,normalization_version,verification_method,verified_at,created_at,updated_at",
      )
      .eq("canonical_identity_key", canonicalIdentityKey)
      .maybeSingle();
  if (existingIdentityError) {
    throw existingIdentityError;
  }
  if (existingIdentity) {
    const { data: existingUser, error: existingUserError } = await input.supabase
      .from("users")
      .select("*")
      .eq("id", existingIdentity.user_id)
      .single<UserRow>();
    if (existingUserError) {
      throw existingUserError;
    }
    return {
      user: existingUser,
      verifiedIdentity: existingIdentity,
    };
  }

  const username = `zkp-seed-${sha256Hex(input.key).slice(0, 18)}`;
  const { data: user, error: userError } = await input.supabase
    .from("users")
    .insert({
      username,
      display_name: "CivicOS ZKP seed voter",
      onboarding_status: "completed",
      verification_level: "fully_verified",
      has_wallet: false,
      wallet_credential_id: null,
      selected_land_id: input.profile.selectedLandId,
      preferred_language: "en",
      public_nickname: null,
      auth_generation: 1,
      account_status: "active",
    })
    .select("*")
    .single<UserRow>();
  if (userError) {
    throw userError;
  }

  const { error: profileError } = await input.supabase
    .from("identity_profiles")
    .insert({
      user_id: user.id,
      passport_scan_completed: true,
      passport_nfc_completed: true,
      national_id_scan_completed: true,
      face_scan_completed: true,
      face_bound_to_identity: true,
      passport_verified_at: new Date().toISOString(),
      national_id_verified_at: new Date().toISOString(),
      face_verified_at: new Date().toISOString(),
      document_country_code: input.profile.documentCountryCode,
      issuing_country_code: input.profile.documentCountryCode,
      home_country_code: input.profile.homeCountryCode,
      home_area_id: input.profile.homeAreaId,
      home_approx_latitude: null,
      home_approx_longitude: null,
      home_location_source: "mock",
      home_location_updated_at: new Date().toISOString(),
    });
  if (profileError) {
    throw profileError;
  }

  const { data: verifiedIdentity, error: identityError } = await input.supabase
    .from("verified_identities")
    .insert({
      user_id: user.id,
      canonical_identity_key: canonicalIdentityKey,
      normalization_version: 1,
      verification_method: "civicos_zkp_seed",
      verified_at: new Date().toISOString(),
    })
    .select(
      "id,user_id,canonical_identity_key,normalization_version,verification_method,verified_at,created_at,updated_at",
    )
    .single();
  if (identityError) {
    throw identityError;
  }

  return {
    user,
    verifiedIdentity,
  };
};

const encryptVoteOpening = (input: {
  pollKey: PollEncryptionKeyRow;
  poll: PollRow;
  option: PollOptionRow;
  optionIndex: number;
  encryptedVoteCommitment: string;
  encryptedVoteRandomness: string;
  voteRandomness: string;
}): JsonValue => {
  const nonce = randomBytes(12);
  const { publicKey: ephemeralPublicKey, privateKey: ephemeralPrivateKey } =
    generateKeyPairSync("x25519");
  const pollPublicKey = createPublicKey({
    key: input.pollKey.public_key_jwk as JsonValue,
    format: "jwk",
  });
  const sharedSecret = diffieHellman({
    privateKey: ephemeralPrivateKey,
    publicKey: pollPublicKey,
  });
  const key = Buffer.from(
    hkdfSync(
      "sha256",
      sharedSecret,
      nonce,
      Buffer.from(
        `CivicOS encrypted vote:${input.poll.id}:${input.poll.option_set_hash}`,
        "utf8",
      ),
      32,
    ),
  );
  const opening = {
    version: "civicos-encrypted-vote-opening-v1",
    pollId: input.poll.id,
    optionId: input.option.id,
    optionIndex: input.optionIndex,
    optionSetHash: assertHex64("optionSetHash", input.poll.option_set_hash),
    encryptedVoteCommitment: input.encryptedVoteCommitment,
    encryptedVoteRandomness: input.encryptedVoteRandomness,
    voteRandomness: input.voteRandomness,
  };
  const aad = Buffer.from(
    canonicalizeJson({
      version: "civicos-encrypted-vote-aad-v1",
      pollId: input.poll.id,
      optionSetHash: input.poll.option_set_hash,
      pollEncryptionKeyId: input.pollKey.key_id,
    }),
    "utf8",
  );
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(canonicalizeJson(opening), "utf8"),
    cipher.final(),
  ]);
  const publicJwk = ephemeralPublicKey.export({ format: "jwk" }) as {
    x?: string;
  };

  return {
    version: "civicos-encrypted-vote-v1",
    pollEncryptionKeyId: input.pollKey.key_id,
    pollEncryptionKeyHash: input.pollKey.public_key_hash,
    encryptedVoteCommitment: input.encryptedVoteCommitment,
    ciphertext: base64url(ciphertext),
    nonce: base64url(nonce),
    authTag: base64url(cipher.getAuthTag()),
    algorithm: "x25519-hkdf-sha256-aes-256-gcm-v1",
    keyAgreement: "x25519",
    kdf: "hkdf-sha256",
    cipher: "aes-256-gcm",
    ephemeralPublicKey: publicJwk.x || "",
    optionSetHash: assertHex64("optionSetHash", input.poll.option_set_hash),
  };
};

const main = async () => {
  const { mode, deleteOriginals } = parseArgs();
  const { voteManifest, tallyManifest } = configureScriptEnv();
  assertCircuitArtifactsExist(voteManifest, tallyManifest);

  const [
    { requireSupabaseAdminClient },
    { default: pollRepository },
    { default: pollDraftService },
    { default: pollEncryptionKeyService },
    { default: credentialRegistryService },
    { default: pollVotingService },
    { default: pollPublicAuditService },
    {
      CIVIC_PRODUCTION_HASH_SUITE,
      CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
      CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
      CIVIC_PRODUCTION_PROOF_PROTOCOL,
      CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
      CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
      hashEncryptedVotePayload,
      hashGroth16VoteProofEnvelope,
      hashGroth16VotePublicInputs,
    },
    {
      CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
      CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
      hashGroth16TallyProofEnvelope,
      hashGroth16TallyPublicInputs,
      hashGroth16TallyOptionCounts,
    },
    { encodeGroth16PublicField },
    { poseidonHashHex64 },
    {
      deriveCircuitValues,
      deriveTallyCircuitValues,
      TALLY_MAX_OPTIONS,
      TALLY_MAX_VOTES,
    },
  ] = await Promise.all([
    import("../src/db/supabaseClient"),
    import("../src/repositories/pollRepository"),
    import("../src/services/pollDraftService"),
    import("../src/services/pollEncryptionKeyService"),
    import("../src/services/credentialRegistryService"),
    import("../src/services/pollVotingService"),
    import("../src/services/pollPublicAuditService"),
    import("../src/services/groth16ProofVerifierService"),
    import("../src/services/groth16TallyProofVerifierService"),
    import("../src/services/groth16SnarkjsVerifierEngine"),
    import("../src/services/poseidonBn254Service"),
    import("../zkp/circuits/scripts/test-vector-lib.mjs"),
  ]);

  const supabase = requireSupabaseAdminClient();
  const polls = (await pollRepository.listAll()).filter(sourcePollAllowed);
  const options = await pollRepository.getOptionsByPollIds(
    polls.map((poll) => poll.id),
  );
  const optionsByPollId = options.reduce<Map<string, PollOptionRow[]>>(
    (acc, option) => {
      const bucket = acc.get(option.poll_id) ?? [];
      bucket.push(option);
      acc.set(option.poll_id, bucket);
      return acc;
    },
    new Map(),
  );

  const sampleVotesPerPoll = Math.min(
    MAX_TALLY_VOTES,
    positiveIntEnv(
      "CIVICOS_ZKP_REPLACE_VOTES_PER_POLL",
      DEFAULT_SAMPLE_VOTES_PER_POLL,
    ),
  );
  const finalStatus = finalPollStatusEnv();
  const plan = polls.map((poll) => {
    const activeOptions = normalizeActiveOptions(optionsByPollId.get(poll.id) ?? []);
    return {
      poll,
      activeOptions,
      voteCount: Math.min(sampleVotesPerPoll, MAX_TALLY_VOTES),
    };
  });

  const invalid = plan.filter(
    (entry) =>
      entry.activeOptions.length < 2 ||
      entry.activeOptions.length > MAX_ZKP_OPTIONS,
  );
  if (invalid.length > 0) {
    throw new Error(
      [
        "Some source polls cannot be converted to production ZKP v1:",
        ...invalid.map(
          ({ poll, activeOptions }) =>
            `  - ${poll.id} (${poll.title}): ${activeOptions.length} active options; expected 2..8.`,
        ),
      ].join("\n"),
    );
  }

  console.log(
    `Found ${plan.length} source poll(s) eligible for production ZKP replacement.`,
  );
  plan.forEach(({ poll, activeOptions, voteCount }) => {
    console.log(
      `  - ${poll.id} "${poll.title}" -> ${activeOptions.length} options, ${voteCount} generated proof-backed votes`,
    );
  });

  if (mode === "dry-run") {
    console.log("Dry run complete. No database rows were changed.");
    return;
  }

  if (!toBoolean(process.env.CIVICOS_ALLOW_ZKP_TEST_DATA_WRITES)) {
    throw new Error(
      "--apply creates synthetic users, credentials, votes, and tally proofs; set CIVICOS_ALLOW_ZKP_TEST_DATA_WRITES=true to acknowledge this is a test-data write.",
    );
  }

  if (
    process.env.NODE_ENV === "production" &&
    !toBoolean(process.env.CIVICOS_ALLOW_PRODUCTION_TEST_DATA_WRITES)
  ) {
    throw new Error(
      "--apply is blocked when NODE_ENV=production unless CIVICOS_ALLOW_PRODUCTION_TEST_DATA_WRITES=true is also set.",
    );
  }

  if (deleteOriginals && !toBoolean(process.env.CIVICOS_ZKP_REPLACE_CONFIRM_DELETE)) {
    throw new Error(
      "--delete-originals requires CIVICOS_ZKP_REPLACE_CONFIRM_DELETE=true.",
    );
  }

  const syntheticOwner = await ensureSyntheticVerifiedUser({
    supabase,
    key: "production-zkp-replacement-owner",
    profile: {
      documentCountryCode: "IR",
      homeCountryCode: "IR",
      homeAreaId: null,
      selectedLandId: null,
    },
  });

  const summaries: ReplacementSummary[] = [];
  for (const { poll: sourcePoll, activeOptions, voteCount } of plan) {
    const pollEncryptionKeyId = `civicos-zkp-${sha256Hex(sourcePoll.id).slice(
      0,
      32,
    )}`;
    const ownerUserId = sourcePoll.created_by_user_id || syntheticOwner.user.id;
    const createResult = await pollDraftService.createPoll(
      pollInputFromSource(sourcePoll, activeOptions, pollEncryptionKeyId),
      ownerUserId,
    );
    if (!createResult.success) {
      throw new Error(
        `Could not create replacement poll for ${sourcePoll.id}: ${createResult.message}`,
      );
    }

    let replacementPoll = await pollRepository.getById(createResult.poll.id);
    if (!replacementPoll) {
      throw new Error("Replacement poll could not be reloaded.");
    }
    const replacementOptions = normalizeActiveOptions(
      await pollRepository.getOptionsByPollId(replacementPoll.id),
    );
    const encryptionKeyResult =
      await pollEncryptionKeyService.getOrCreatePublicKeyForPoll(
        replacementPoll.id,
      );
    if (!encryptionKeyResult.success) {
      throw new Error(encryptionKeyResult.message);
    }
    const { data: pollKey, error: pollKeyError } = await supabase
      .from("poll_encryption_keys")
      .select("*")
      .eq("key_id", replacementPoll.poll_encryption_key_id)
      .single<PollEncryptionKeyRow>();
    if (pollKeyError) {
      throw pollKeyError;
    }

    const pollPolicyHash = assertHex64(
      "pollPolicyHash",
      replacementPoll.poll_policy_hash,
    );
    const credentialSchemaHash = assertHex64(
      "credentialSchemaHash",
      replacementPoll.credential_schema_hash,
    );
    const optionSetHash = assertHex64(
      "optionSetHash",
      replacementPoll.option_set_hash,
    );
    const profile = selectProfileForPoll(replacementPoll);
    const generatedVotes: GeneratedVoteMaterial[] = [];

    for (let voteIndex = 0; voteIndex < voteCount; voteIndex += 1) {
      const optionIndex = voteIndex % replacementOptions.length;
      const selectedOption = replacementOptions[optionIndex];
      const identitySecret = sha256Hex(
        `civicos-zkp-replacement|identity-secret|${replacementPoll.id}|${voteIndex}`,
      );
      const encryptedVoteRandomness = sha256Hex(
        `civicos-zkp-replacement|encrypted-randomness|${replacementPoll.id}|${voteIndex}`,
      );
      const voteRandomness = sha256Hex(
        `civicos-zkp-replacement|vote-randomness|${replacementPoll.id}|${voteIndex}`,
      );
      const claimsHash = sha256Hex(
        canonicalizeJson({
          version: "civicos-zkp-seed-claims-v1",
          pollId: replacementPoll.id,
          voteIndex,
          pollPolicyHash,
          credentialSchemaHash,
        }),
      );
      const voter = await ensureSyntheticVerifiedUser({
        supabase,
        key: `${replacementPoll.id}|${voteIndex}`,
        profile,
      });
      const identityKeyHash =
        await credentialRegistryService.deriveIdentityKeyHash(
          voter.verifiedIdentity.canonical_identity_key,
        );
      const credentialCommitment = await poseidonHashHex64([
        identitySecret,
        identityKeyHash,
        credentialSchemaHash,
        claimsHash,
      ]);
      const registryIssue =
        await credentialRegistryService.issueCredentialRegistryEntry({
          verifiedIdentity: {
            id: voter.verifiedIdentity.id,
            canonical_identity_key:
              voter.verifiedIdentity.canonical_identity_key,
          },
          credentialCommitment,
          credentialSchemaHash,
          claimsHash,
          credentialIssuerId: "did:iland:backend:zkp-seed-v1",
        });

      const witness = {
        pollId: encodeGroth16PublicField("pollId", replacementPoll.id),
        pollPolicyHash: encodeGroth16PublicField(
          "pollPolicyHash",
          pollPolicyHash,
        ),
        credentialSchemaHash: encodeGroth16PublicField(
          "credentialSchemaHash",
          credentialSchemaHash,
        ),
        optionSetHash: encodeGroth16PublicField("optionSetHash", optionSetHash),
        optionCount: String(replacementOptions.length),
        identitySecret: hexFieldToDecimal(identitySecret),
        identityKeyHash: hexFieldToDecimal(identityKeyHash),
        claimsHash: hexFieldToDecimal(claimsHash),
        optionIndex: String(optionIndex),
        optionIndexBits: optionBits(optionIndex),
        encryptedVoteRandomness: hexFieldToDecimal(encryptedVoteRandomness),
        voteRandomness: hexFieldToDecimal(voteRandomness),
        credentialRootSiblings: registryIssue.merklePath.siblings.map(
          hexFieldToDecimal,
        ),
        credentialRootPathIndices: registryIssue.merklePath.pathIndices.map(
          String,
        ),
        credentialRoot: hexFieldToDecimal(registryIssue.merklePath.root),
      };
      const derived = await deriveCircuitValues(witness);
      const encryptedVoteCommitment = fieldElementToHex64(
        derived.input.encryptedVoteCommitment,
      );
      const voteCommitment = fieldElementToHex64(derived.input.voteCommitment);
      const nullifier = fieldElementToHex64(derived.input.nullifier);
      const encryptedVote = encryptVoteOpening({
        pollKey,
        poll: replacementPoll,
        option: selectedOption,
        optionIndex,
        encryptedVoteCommitment,
        encryptedVoteRandomness,
        voteRandomness,
      });
      const encryptedVoteHash = hashEncryptedVotePayload(encryptedVote);
      const { proof } = runGroth16Proof({
        circuitName: "credential_commitment_vote",
        manifest: voteManifest,
        manifestPath: voteManifestPath,
        witnessInput: {
          ...witness,
          credentialRoot: derived.input.credentialRoot,
          nullifier: derived.input.nullifier,
          voteCommitment: derived.input.voteCommitment,
          encryptedVoteCommitment: derived.input.encryptedVoteCommitment,
        },
      });
      const publicInputs = {
        version: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
        pollId: replacementPoll.id,
        pollPolicyHash,
        credentialSchemaHash,
        optionSetHash,
        optionCount: replacementOptions.length,
        credentialRoot: registryIssue.merklePath.root,
        nullifier,
        voteCommitment,
        encryptedVoteHash,
        encryptedVoteCommitment,
        verificationMethodVersion: "civicos-mobile-verification-v1",
        proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
        hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
        circuitId: voteManifest.circuitId,
        verifierKeyHash: voteManifest.verifierKeyHash,
        publicInputSchemaVersion: voteManifest.publicInputSchemaVersion,
      };
      const proofEnvelope = {
        version: CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
        protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
        proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
        status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
        hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
        circuitId: voteManifest.circuitId,
        verifierKeyHash: voteManifest.verifierKeyHash,
        publicInputSchemaVersion: voteManifest.publicInputSchemaVersion,
        proof,
        publicInputs,
        publicInputsHash: hashGroth16VotePublicInputs(publicInputs),
      };
      const submission = await pollVotingService.submitVote({
        pollId: replacementPoll.id,
        optionId: selectedOption.id,
        viewer: voter.user,
        privacy: {
          version: "civicos-vote-privacy-v1",
          votePrivacyMode: "zk_secret_ballot_v1",
          hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
          nullifier,
          voteCommitment,
          encryptedVoteHash,
          encryptedVoteCommitment,
          proof: proofEnvelope,
        },
        expectedVoteCommitment: voteCommitment,
        encryptedVote,
      });
      if (!submission.success) {
        throw new Error(
          `Generated vote ${voteIndex} for ${replacementPoll.id} was rejected: ${submission.message}`,
        );
      }

      generatedVotes.push({
        optionId: selectedOption.id,
        optionIndex,
        optionIndexBits: optionBits(optionIndex),
        identitySecret,
        identityKeyHash,
        claimsHash,
        encryptedVoteRandomness,
        voteRandomness,
        nullifier,
        voteCommitment,
        encryptedVoteHash,
        encryptedVoteCommitment,
        proofEnvelopeHash: hashGroth16VoteProofEnvelope(proofEnvelope),
        acceptedAt: submission.viewerVote.submittedAt,
      });
    }

    const paddedVotes = Array.from(
      { length: TALLY_MAX_VOTES as number },
      (_, index) => generatedVotes[index] ?? null,
    );
    const optionCounts = Array.from(
      { length: TALLY_MAX_OPTIONS as number },
      (_, optionIndex) =>
        generatedVotes.filter((vote) => vote.optionIndex === optionIndex)
          .length,
    );
    const tallyWitness = {
      pollId: encodeGroth16PublicField("pollId", replacementPoll.id),
      pollPolicyHash: encodeGroth16PublicField(
        "pollPolicyHash",
        pollPolicyHash,
      ),
      credentialSchemaHash: encodeGroth16PublicField(
        "credentialSchemaHash",
        credentialSchemaHash,
      ),
      optionSetHash: encodeGroth16PublicField("optionSetHash", optionSetHash),
      optionCount: String(replacementOptions.length),
      isActive: paddedVotes.map((vote) => (vote ? "1" : "0")),
      nullifiers: paddedVotes.map((vote) =>
        vote ? hexFieldToDecimal(vote.nullifier) : "0",
      ),
      encryptedVoteCommitments: paddedVotes.map((vote) =>
        vote ? hexFieldToDecimal(vote.encryptedVoteCommitment) : "0",
      ),
      encryptedVoteRandomness: paddedVotes.map((vote) =>
        vote ? hexFieldToDecimal(vote.encryptedVoteRandomness) : "0",
      ),
      voteRandomness: paddedVotes.map((vote) =>
        vote ? hexFieldToDecimal(vote.voteRandomness) : "0",
      ),
      optionSelections: paddedVotes.map((vote) =>
        Array.from({ length: TALLY_MAX_OPTIONS as number }, (_, optionIndex) =>
          vote && vote.optionIndex === optionIndex ? "1" : "0",
        ),
      ),
      optionCounts: optionCounts.map(String),
    };
    const derivedTally = await deriveTallyCircuitValues(tallyWitness);
    const { proof: tallyProof } = runGroth16Proof({
      circuitName: "encrypted_choice_tally",
      manifest: tallyManifest,
      manifestPath: tallyManifestPath,
      witnessInput: {
        ...tallyWitness,
        nullifierRoot: derivedTally.input.nullifierRoot,
        voteCommitmentRoot: derivedTally.input.voteCommitmentRoot,
        encryptedVoteRoot: derivedTally.input.encryptedVoteRoot,
        acceptedVoteCount: derivedTally.input.acceptedVoteCount,
        optionCountsHash: derivedTally.input.optionCountsHash,
      },
    });
    const tallyOptionResults = replacementOptions.map((option, optionIndex) => ({
      optionId: option.id,
      count: optionCounts[optionIndex] ?? 0,
    }));
    const tallyPublicInputs = {
      version: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
      pollId: replacementPoll.id,
      pollPolicyHash,
      credentialSchemaHash,
      optionSetHash,
      optionCount: replacementOptions.length,
      nullifierRoot: fieldElementToHex64(derivedTally.input.nullifierRoot),
      voteCommitmentRoot: fieldElementToHex64(
        derivedTally.input.voteCommitmentRoot,
      ),
      encryptedVoteRoot: fieldElementToHex64(
        derivedTally.input.encryptedVoteRoot,
      ),
      acceptedVoteCount: generatedVotes.length,
      optionResults: tallyOptionResults,
      optionCountsHash: await hashGroth16TallyOptionCounts(tallyOptionResults),
      proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
      hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
      circuitId: tallyManifest.circuitId,
      verifierKeyHash: tallyManifest.verifierKeyHash,
      publicInputSchemaVersion: tallyManifest.publicInputSchemaVersion,
    };
    const tallyEnvelope = {
      version: CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
      protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
      proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
      status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
      hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
      circuitId: tallyManifest.circuitId,
      verifierKeyHash: tallyManifest.verifierKeyHash,
      publicInputSchemaVersion: tallyManifest.publicInputSchemaVersion,
      proof: tallyProof,
      publicInputs: tallyPublicInputs,
      publicInputsHash: hashGroth16TallyPublicInputs(tallyPublicInputs),
    };
    const tallySubmission = await pollPublicAuditService.submitTallyProof({
      pollId: replacementPoll.id,
      viewerUserId: ownerUserId,
      proof: tallyEnvelope,
    });
    if (!tallySubmission.success) {
      throw new Error(
        `Generated tally proof for ${replacementPoll.id} was rejected: ${tallySubmission.message}`,
      );
    }

    if (finalStatus === "closed") {
      const { error: closeError } = await supabase
        .from("polls")
        .update({ status: "closed" })
        .eq("id", replacementPoll.id);
      if (closeError) {
        throw closeError;
      }
      replacementPoll = await pollRepository.getById(replacementPoll.id);
      if (!replacementPoll) {
        throw new Error("Closed replacement poll could not be reloaded.");
      }
    }

    const tallyProofHash = hashGroth16TallyProofEnvelope(tallyEnvelope);
    summaries.push({
      sourcePollId: sourcePoll.id,
      replacementPollId: replacementPoll.id,
      title: replacementPoll.title,
      acceptedVoteCount: generatedVotes.length,
      tallyProofHash,
      resultHash: tallySubmission.tallyProof.resultHash,
      finalStatus,
    });
    console.log(
      `Created ZKP replacement poll ${replacementPoll.id} for ${sourcePoll.id}; votes=${generatedVotes.length}; tallyProof=${tallyProofHash}`,
    );
  }

  if (deleteOriginals && summaries.length > 0) {
    const { error } = await supabase
      .from("polls")
      .delete()
      .in(
        "id",
        summaries.map((summary) => summary.sourcePollId),
      );
    if (error) {
      throw error;
    }
    console.log(`Deleted ${summaries.length} original source poll(s).`);
  }

  const reportPath = resolve(
    backendRoot,
    `tmp/zkp-replacement-polls/${new Date()
      .toISOString()
      .replace(/[:.]/g, "-")}.json`,
  );
  writeJson(reportPath, {
    version: "civicos-zkp-replacement-report-v1",
    generatedAt: new Date().toISOString(),
    mode,
    deleteOriginals,
    summaries,
  });
  console.log(`Report written to ${reportPath}`);
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
