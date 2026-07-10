#!/usr/bin/env node

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import {
  clusterApiUrl,
  Connection,
  LAMPORTS_PER_SOL,
  PublicKey,
} from "@solana/web3.js";

const DEFAULT_PROGRAM_ID = "FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo";
const DEFAULT_CLUSTER = "devnet";

const args = process.argv.slice(2);
const helpRequested = args.includes("--help") || args.includes("-h");
const preflightOnly =
  args.includes("--preflight-only") ||
  process.env.CIVICOS_PHASE7_PREFLIGHT_ONLY === "true";
const confirmSend = process.env.CIVICOS_PHASE7_CONFIRM_SEND === "true";

const usage = () => {
  console.error(`Usage:
  node scripts/phase7-devnet-acceptance.mjs --preflight-only
  CIVICOS_PHASE7_CONFIRM_SEND=true \\
  CIVICOS_PHASE7_BACKEND_URL=https://... \\
  CIVICOS_PHASE7_BEARER_TOKEN=<access token> \\
  CIVICOS_PHASE7_POLL_ID=<poll id> \\
  [CIVICOS_PHASE7_RECEIPT_VOTE_COMMITMENT=<64-byte hex>] \\
    node scripts/phase7-devnet-acceptance.mjs

What it does:
  1. Checks the configured Solana audit program exists on the selected cluster.
  2. Fetches public audit material from the backend.
  3. When explicitly confirmed, calls POST /polls/:id/audit/publish.
  4. Fetches audit/receipt material again and runs scripts/verify-public-audit.mjs.

This script does not create votes or generate mobile proofs. It verifies the
Phase 7 publication leg after a production ZKP poll already has accepted
proof-backed votes and, for final publication, a verified tally proof.
`);
};

if (helpRequested) {
  usage();
  process.exit(0);
}

const requireEnv = (name) => {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
};

const optionalEnv = (name) => process.env[name]?.trim() || null;

const normalizeBaseUrl = (value) => value.replace(/\/+$/u, "");

const cluster = optionalEnv("SOLANA_AUDIT_CLUSTER") || DEFAULT_CLUSTER;
const rpcUrl =
  optionalEnv("SOLANA_AUDIT_RPC_URL") ||
  (cluster === "localnet" ? "http://127.0.0.1:8899" : clusterApiUrl(cluster));
const programId = new PublicKey(
  optionalEnv("SOLANA_AUDIT_PROGRAM_ID") || DEFAULT_PROGRAM_ID,
);
const feePayerPublicKey = optionalEnv("SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY");
const registryAuthority = optionalEnv("SOLANA_AUDIT_REGISTRY_AUTHORITY");
const rootPublisherPublicKey =
  optionalEnv("SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY") || feePayerPublicKey;

const connection = new Connection(rpcUrl, "confirmed");
const programAccount = await connection.getAccountInfo(programId);
if (!programAccount) {
  throw new Error(
    `CivicOS audit program ${programId.toBase58()} was not found on ${cluster} (${rpcUrl}).`,
  );
}
if (!programAccount.executable) {
  throw new Error(
    `CivicOS audit program ${programId.toBase58()} exists on ${cluster}, but is not executable.`,
  );
}

console.log("Phase 7 Solana preflight OK");
console.log(`  cluster=${cluster}`);
console.log(`  rpcUrl=${rpcUrl}`);
console.log(`  programId=${programId.toBase58()}`);
console.log(`  programAccountDataBytes=${programAccount.data.length}`);
if (registryAuthority) {
  console.log(`  registryAuthority=${registryAuthority}`);
}
if (rootPublisherPublicKey) {
  console.log(`  rootPublisher=${rootPublisherPublicKey}`);
}
if (
  registryAuthority &&
  rootPublisherPublicKey &&
  registryAuthority === rootPublisherPublicKey
) {
  throw new Error(
    "Phase 8 governance requires SOLANA_AUDIT_REGISTRY_AUTHORITY and SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY to be different.",
  );
}

if (feePayerPublicKey) {
  const balanceLamports = await connection.getBalance(
    new PublicKey(feePayerPublicKey),
    "confirmed",
  );
  console.log(
    `  feePayer=${feePayerPublicKey} balance=${balanceLamports / LAMPORTS_PER_SOL} SOL`,
  );
}

if (preflightOnly) {
  console.log("Preflight-only mode complete. No backend publication was called.");
  process.exit(0);
}

if (!confirmSend) {
  usage();
  throw new Error(
    "Refusing to call backend publication without CIVICOS_PHASE7_CONFIRM_SEND=true.",
  );
}

const backendUrl = normalizeBaseUrl(requireEnv("CIVICOS_PHASE7_BACKEND_URL"));
const bearerToken = requireEnv("CIVICOS_PHASE7_BEARER_TOKEN");
const pollId = requireEnv("CIVICOS_PHASE7_POLL_ID");
const receiptVoteCommitment = optionalEnv("CIVICOS_PHASE7_RECEIPT_VOTE_COMMITMENT");

const requestJson = async (path, options = {}) => {
  const response = await fetch(`${backendUrl}${path}`, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : null),
      ...(options.authenticated ? { Authorization: `Bearer ${bearerToken}` } : null),
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  const json = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(
      `${options.method || "GET"} ${path} failed with HTTP ${response.status}: ${JSON.stringify(json)}`,
    );
  }
  return json;
};

const pollPath = `/polls/${encodeURIComponent(pollId)}`;
const auditPath = `${pollPath}/audit`;
const publishPath = `${pollPath}/audit/publish`;

const beforeAudit = await requestJson(auditPath);
if (beforeAudit.acceptedVoteCount <= 0) {
  throw new Error("Poll has no accepted proof-backed votes to publish.");
}

console.log("Calling backend audit publication route...");
const publication = await requestJson(publishPath, {
  method: "POST",
  authenticated: true,
});
if (publication.success !== true) {
  throw new Error(`Publication failed: ${JSON.stringify(publication)}`);
}

const afterAudit = await requestJson(auditPath);
const receipt = receiptVoteCommitment
  ? await requestJson(
      `${pollPath}/receipt/${encodeURIComponent(receiptVoteCommitment)}`,
    )
  : null;

const artifactDir = resolve(
  process.cwd(),
  "tmp",
  "phase7",
  `${pollId}-${new Date().toISOString().replace(/[:.]/gu, "-")}`,
);
mkdirSync(artifactDir, { recursive: true });
const auditFile = join(artifactDir, "audit.json");
const receiptFile = receipt ? join(artifactDir, "receipt.json") : null;
const publicationFile = join(artifactDir, "publication.json");
writeFileSync(auditFile, `${JSON.stringify(afterAudit, null, 2)}\n`);
writeFileSync(publicationFile, `${JSON.stringify(publication, null, 2)}\n`);
if (receipt && receiptFile) {
  writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`);
}

const verifierArgs = ["scripts/verify-public-audit.mjs", "--audit", auditFile];
if (receiptFile) {
  verifierArgs.push("--receipt", receiptFile);
}
const verifier = spawnSync(process.execPath, verifierArgs, {
  cwd: process.cwd(),
  encoding: "utf8",
});
if (verifier.stdout) {
  process.stdout.write(verifier.stdout);
}
if (verifier.stderr) {
  process.stderr.write(verifier.stderr);
}
if (verifier.status !== 0) {
  throw new Error(`Public audit verifier failed with status ${verifier.status}.`);
}

console.log("Phase 7 publication acceptance OK");
console.log(`  artifacts=${artifactDir}`);
console.log(`  publicationStatus=${afterAudit.publicationStatus}`);
console.log(`  rootCommits=${afterAudit.rootCommits.length}`);
console.log(
  `  finalResultTx=${publication.publication?.finalResultSignature || "(not published)"}`,
);
