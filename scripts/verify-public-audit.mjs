#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { buildPoseidon } from "circomlibjs";

const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const PUBLIC_AUDIT_RESULT_HASH_VERSION = "civicos-public-audit-result-v1";
const POSEIDON_AUDIT_TREE_DEPTH = 6;
const POSEIDON_AUDIT_LEAF_TAGS = Object.freeze({
  nullifier: 1101,
  vote_commitment: 1102,
  encrypted_vote: 1103,
});

const usage = () => {
  console.error(`Usage:
  node scripts/verify-public-audit.mjs --audit audit.json [--receipt receipt.json]

Checks:
  - recomputes audit.resultHash from the public audit JSON
  - verifies receipt.voteCommitmentLeafHash from receipt.voteCommitment
  - verifies receipt.merklePath against receipt.root
  - checks receipt.root matches audit.auditBatches[receipt.batchIndex]
`);
};

const args = process.argv.slice(2);
const getArg = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
};

const auditPath = getArg("--audit");
const receiptPath = getArg("--receipt");
const helpRequested = args.includes("--help") || args.includes("-h");
if (!auditPath || helpRequested) {
  usage();
  process.exit(helpRequested ? 0 : 2);
}

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

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
      .sort((left, right) => left.localeCompare(right))
      .reduce((record, key) => {
        const normalized = normalizeJsonValue(value[key]);
        if (normalized !== undefined) {
          record[key] = normalized;
        }
        return record;
      }, {});
  }
  throw new TypeError("Canonical JSON can only encode JSON-compatible values.");
};

const canonicalizeJson = (value) => JSON.stringify(normalizeJsonValue(value));
const hashCanonicalJson = (value) =>
  createHash("sha256").update(canonicalizeJson(value), "utf8").digest("hex");

const normalizeHex64 = (value, name) => {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string.`);
  }
  const normalized = value.trim().toLowerCase();
  if (!HEX_64_PATTERN.test(normalized)) {
    throw new TypeError(`${name} must be a 32-byte lowercase hex string.`);
  }
  return normalized;
};

const normalizeField = (value) => {
  if (typeof value === "bigint") {
    return value % BN254_SCALAR_FIELD;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new TypeError("Expected a non-negative integer field element.");
    }
    return BigInt(value) % BN254_SCALAR_FIELD;
  }
  const normalized = String(value).trim().toLowerCase();
  if (HEX_64_PATTERN.test(normalized)) {
    return BigInt(`0x${normalized}`) % BN254_SCALAR_FIELD;
  }
  if (DECIMAL_PATTERN.test(normalized)) {
    return BigInt(normalized) % BN254_SCALAR_FIELD;
  }
  throw new TypeError("Expected a 32-byte hex or decimal field element.");
};

const fieldToHex64 = (value) => normalizeField(value).toString(16).padStart(64, "0");

let poseidonPromise = null;
const poseidonHashHex64 = async (inputs) => {
  poseidonPromise ??= buildPoseidon();
  const poseidon = await poseidonPromise;
  const output = poseidon(inputs.map((input) => normalizeField(input)));
  return fieldToHex64(poseidon.F.toString(output));
};

const hashPoseidonAuditLeaf = async (kind, value) =>
  poseidonHashHex64([POSEIDON_AUDIT_LEAF_TAGS[kind], normalizeHex64(value, kind)]);

const hashPoseidonAuditNode = async (left, right) =>
  poseidonHashHex64([
    fieldToHex64(normalizeHex64(left, "left")),
    fieldToHex64(normalizeHex64(right, "right")),
  ]);

const verifyPoseidonAuditMerkleProof = async ({ leafHash, root, proof }) => {
  let computedRoot = normalizeHex64(leafHash, "leafHash");
  const normalizedRoot = normalizeHex64(root, "root");
  if (!Array.isArray(proof) || proof.length !== POSEIDON_AUDIT_TREE_DEPTH) {
    return false;
  }
  for (const step of proof) {
    if (step.position !== "left" && step.position !== "right") {
      return false;
    }
    const sibling = normalizeHex64(step.hash, "sibling hash");
    computedRoot =
      step.position === "left"
        ? await hashPoseidonAuditNode(sibling, computedRoot)
        : await hashPoseidonAuditNode(computedRoot, sibling);
  }
  return computedRoot === normalizedRoot;
};

const buildResultHash = (audit) =>
  hashCanonicalJson({
    version: PUBLIC_AUDIT_RESULT_HASH_VERSION,
    pollId: audit.pollId,
    pollStatus: audit.pollStatus,
    pollPolicyHash: audit.pollPolicyHash ?? null,
    credentialSchemaHash: audit.credentialSchemaHash ?? null,
    optionSetHash: audit.optionSetHash ?? null,
    acceptedVoteCount: audit.acceptedVoteCount,
    totalValidVoteCount: audit.totalValidVoteCount,
    optionCount: audit.finalResult.optionResults.length,
    finalNullifierRoot: audit.trees.nullifier.root,
    finalVoteCommitmentRoot: audit.trees.voteCommitment.root,
    finalEncryptedVoteRoot: audit.trees.encryptedVote.root,
    tallyProofHash: audit.tallyProofHash ?? null,
    tallyPublicInputsHash: audit.tallyPublicInputsHash ?? null,
    tallyVerifierKeyHash: audit.tallyProof?.tallyVerifierKeyHash ?? null,
    tallyCircuitId: audit.tallyProof?.tallyCircuitId ?? null,
    result: {
      totalVotes: audit.finalResult.totalVotes,
      optionResults: audit.finalResult.optionResults.map((entry) => ({
        optionId: entry.optionId,
        label: entry.label,
        count: entry.count,
      })),
    },
  });

const assert = (condition, message) => {
  if (!condition) {
    throw new Error(message);
  }
};

const audit = readJson(auditPath);
assert(audit.version === "civicos-public-audit-v1", "Unsupported audit version.");
assert(audit.trees?.voteCommitment, "Audit is missing vote commitment tree.");
assert(
  audit.trees.voteCommitment.hashAlgorithm === "poseidon-bn254",
  "This verifier currently supports production Poseidon audit trees only.",
);

const recomputedResultHash = buildResultHash(audit);
assert(
  recomputedResultHash === audit.resultHash,
  `resultHash mismatch: expected ${audit.resultHash}, recomputed ${recomputedResultHash}`,
);

const checks = [
  `resultHash=${recomputedResultHash}`,
  `acceptedVoteCount=${audit.acceptedVoteCount}`,
];

if (receiptPath) {
  const receipt = readJson(receiptPath);
  assert(receipt.included === true, "Receipt is not included.");
  assert(
    receipt.pollId === audit.pollId,
    `Receipt pollId ${receipt.pollId} does not match audit pollId ${audit.pollId}.`,
  );
  const leafHash = await hashPoseidonAuditLeaf(
    "vote_commitment",
    receipt.voteCommitment,
  );
  assert(
    leafHash === receipt.voteCommitmentLeafHash,
    `voteCommitmentLeafHash mismatch: expected ${receipt.voteCommitmentLeafHash}, recomputed ${leafHash}`,
  );
  const proofOk = await verifyPoseidonAuditMerkleProof({
    leafHash: receipt.voteCommitmentLeafHash,
    root: receipt.root,
    proof: receipt.merklePath,
  });
  assert(proofOk, "Receipt Merkle path does not verify.");

  const batch = audit.auditBatches.find(
    (entry) => entry.batchIndex === receipt.batchIndex,
  );
  assert(batch, `Audit batch ${receipt.batchIndex} was not found.`);
  assert(
    batch.voteCommitmentRoot === receipt.root,
    "Receipt root does not match audit batch voteCommitmentRoot.",
  );
  if (receipt.batchStatus === "published_on_chain") {
    assert(batch.publication, "Receipt is published but audit batch has no publication.");
    assert(
      batch.publication.transactionSignature === receipt.solanaTx,
      "Receipt Solana transaction does not match audit batch publication.",
    );
  }
  checks.push(`receiptBatch=${receipt.batchIndex}`);
  checks.push(`receiptRoot=${receipt.root}`);
}

console.log("CivicOS public audit verification OK");
for (const check of checks) {
  console.log(`  ${check}`);
}
