#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
const allowPartial = process.env.CIVICOS_PHASE7_ALLOW_PARTIAL === "true";
const allowMissingReceipt =
  process.env.CIVICOS_PHASE7_ALLOW_MISSING_RECEIPT === "true";

const usage = () => {
  console.error(`Usage:
  node scripts/phase7-devnet-acceptance.mjs --preflight-only
  CIVICOS_PHASE7_CONFIRM_SEND=true \\
  CIVICOS_PHASE7_BACKEND_URL=https://... \\
  CIVICOS_PHASE7_BEARER_TOKEN=<access token> \\
  CIVICOS_PHASE7_POLL_ID=<poll id> \\
  [CIVICOS_PHASE7_RECEIPT_VOTE_COMMITMENT=<64-byte hex>] \\
  [CIVICOS_PHASE7_DUPLICATE_VOTE_PAYLOAD_FILE=tmp/phase7/vote-payload.json] \\
    node scripts/phase7-devnet-acceptance.mjs

What it does:
  1. Checks the configured Solana audit program exists on the selected cluster.
  2. Captures backend /health/zkp and public audit material.
  3. Optionally replays a saved vote payload and expects duplicate-nullifier rejection.
  4. When explicitly confirmed, calls POST /polls/:id/audit/publish.
  5. Fetches audit/receipt material again and runs scripts/verify-public-audit.mjs.
  6. Writes JSON artifacts and PHASE7-TRANSCRIPT.md under tmp/phase7/.

This script does not create votes or generate mobile proofs. It verifies the
Phase 7 publication leg after a production ZKP poll already has accepted
proof-backed votes and, for final publication, a verified tally proof.

By default, confirmed runs are strict and require a receipt vote commitment,
published roots, a verified tally proof, and a final result transaction. For a
partial publication rehearsal only, set CIVICOS_PHASE7_ALLOW_PARTIAL=true.
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
const duplicateVotePayloadFile = optionalEnv(
  "CIVICOS_PHASE7_DUPLICATE_VOTE_PAYLOAD_FILE",
);

if (!receiptVoteCommitment && !allowMissingReceipt && !allowPartial) {
  throw new Error(
    "CIVICOS_PHASE7_RECEIPT_VOTE_COMMITMENT is required for strict Phase 7 acceptance. Set CIVICOS_PHASE7_ALLOW_MISSING_RECEIPT=true only for a partial diagnostic run.",
  );
}

const artifactDir = resolve(
  process.cwd(),
  optionalEnv("CIVICOS_PHASE7_ARTIFACT_DIR") ||
    join(
      "tmp",
      "phase7",
      `${pollId}-${new Date().toISOString().replace(/[:.]/gu, "-")}`,
    ),
);
mkdirSync(artifactDir, { recursive: true });

const writeJsonArtifact = (name, value) => {
  const file = join(artifactDir, name);
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
  return file;
};

const transcriptLines = [
  "# CivicOS Phase 7 Devnet Acceptance Transcript",
  "",
  `Generated: ${new Date().toISOString()}`,
  "",
  "## Inputs",
  "",
  `- Backend: ${backendUrl}`,
  `- Poll ID: ${pollId}`,
  `- Cluster: ${cluster}`,
  `- RPC URL: ${rpcUrl}`,
  `- Program ID: ${programId.toBase58()}`,
  `- Registry authority: ${registryAuthority || "(not set)"}`,
  `- Root publisher: ${rootPublisherPublicKey || "(not set)"}`,
  `- Fee payer: ${feePayerPublicKey || "(not set)"}`,
  `- Strict mode: ${allowPartial ? "no" : "yes"}`,
  `- Receipt commitment supplied: ${receiptVoteCommitment ? "yes" : "no"}`,
  `- Duplicate vote payload supplied: ${duplicateVotePayloadFile ? "yes" : "no"}`,
  "",
];

const pushTranscript = (...lines) => {
  transcriptLines.push(...lines);
};

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
  if (options.allowHttpError) {
    return {
      ok: response.ok,
      status: response.status,
      body: json,
    };
  }
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

const zkpHealthResponse = await requestJson("/health/zkp", {
  allowHttpError: true,
});
const zkpHealthFile = writeJsonArtifact("health-zkp.json", zkpHealthResponse);
if (!zkpHealthResponse.ok) {
  throw new Error(
    `Backend /health/zkp is not healthy: HTTP ${zkpHealthResponse.status}; see ${zkpHealthFile}`,
  );
}
pushTranscript(
  "## Backend ZKP Health",
  "",
  `- Status: ${zkpHealthResponse.body?.status || "(unknown)"}`,
  `- Vote verifier configured: ${Boolean(
    zkpHealthResponse.body?.checks?.voteGroth16Verifier?.configured,
  )}`,
  `- Tally verifier configured: ${Boolean(
    zkpHealthResponse.body?.checks?.tallyGroth16Verifier?.configured,
  )}`,
  `- Ballot custody mode: ${
    zkpHealthResponse.body?.checks?.ballotCustody?.mode || "(not reported)"
  }`,
  "",
);

const beforeAudit = await requestJson(auditPath);
writeJsonArtifact("audit-before.json", beforeAudit);
if (beforeAudit.acceptedVoteCount <= 0) {
  throw new Error("Poll has no accepted proof-backed votes to publish.");
}
pushTranscript(
  "## Audit Before Publication",
  "",
  `- Publication status: ${beforeAudit.publicationStatus}`,
  `- Accepted votes: ${beforeAudit.acceptedVoteCount}`,
  `- Root commits: ${beforeAudit.rootCommits?.length || 0}`,
  `- Tally proof hash: ${beforeAudit.tallyProofHash || "(none)"}`,
  "",
);

let duplicateVoteDrill = null;
if (duplicateVotePayloadFile) {
  const duplicatePayload = JSON.parse(readFileSync(duplicateVotePayloadFile, "utf8"));
  duplicateVoteDrill = await requestJson(`${pollPath}/vote`, {
    method: "POST",
    authenticated: true,
    body: JSON.stringify(duplicatePayload),
    allowHttpError: true,
  });
  writeJsonArtifact("duplicate-vote-response.json", duplicateVoteDrill);
  if (duplicateVoteDrill.ok) {
    throw new Error(
      "Duplicate vote drill unexpectedly succeeded. Expected ALREADY_VOTED/duplicate_nullifier rejection.",
    );
  }
  if (
    duplicateVoteDrill.status !== 409 ||
    duplicateVoteDrill.body?.errorCode !== "ALREADY_VOTED"
  ) {
    throw new Error(
      `Duplicate vote drill returned unexpected response: HTTP ${duplicateVoteDrill.status} ${JSON.stringify(duplicateVoteDrill.body)}`,
    );
  }
  pushTranscript(
    "## Negative Drill: Duplicate Nullifier",
    "",
    `- HTTP status: ${duplicateVoteDrill.status}`,
    `- Error code: ${duplicateVoteDrill.body?.errorCode || "(none)"}`,
    `- Message: ${duplicateVoteDrill.body?.message || "(none)"}`,
    "",
  );
} else {
  pushTranscript(
    "## Negative Drill: Duplicate Nullifier",
    "",
    "- Skipped: set `CIVICOS_PHASE7_DUPLICATE_VOTE_PAYLOAD_FILE` to replay the phone-generated vote payload and require duplicate-nullifier rejection.",
    "",
  );
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
writeJsonArtifact("audit-after.json", afterAudit);
const receipt = receiptVoteCommitment
  ? await requestJson(
      `${pollPath}/receipt/${encodeURIComponent(receiptVoteCommitment)}`,
    )
  : null;

const auditFile = writeJsonArtifact("audit.json", afterAudit);
const receiptFile = receipt ? join(artifactDir, "receipt.json") : null;
const publicationFile = writeJsonArtifact("publication.json", publication);
if (receipt && receiptFile) {
  writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`);
}

if (!allowPartial) {
  if (afterAudit.publicationStatus !== "published_on_chain") {
    throw new Error(
      `Strict Phase 7 acceptance requires publicationStatus=published_on_chain; got ${afterAudit.publicationStatus}.`,
    );
  }
  if (!Array.isArray(afterAudit.rootCommits) || afterAudit.rootCommits.length === 0) {
    throw new Error("Strict Phase 7 acceptance requires at least one published root commit.");
  }
  if (!afterAudit.tallyProofHash) {
    throw new Error("Strict Phase 7 acceptance requires a verified tally proof hash.");
  }
  if (!publication.publication?.finalResultSignature) {
    throw new Error("Strict Phase 7 acceptance requires a final result Solana transaction.");
  }
  if (!receipt) {
    throw new Error("Strict Phase 7 acceptance requires a receipt inclusion artifact.");
  }
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
writeFileSync(
  join(artifactDir, "public-audit-verifier.txt"),
  `${verifier.stdout || ""}${verifier.stderr || ""}`,
);

const rootTransactions = (afterAudit.rootCommits || [])
  .map((commit) => commit.transactionSignature)
  .filter(Boolean);
pushTranscript(
  "## Publication Result",
  "",
  `- Publication status: ${afterAudit.publicationStatus}`,
  `- Accepted votes: ${afterAudit.acceptedVoteCount}`,
  `- Result hash: ${afterAudit.resultHash}`,
  `- Tally proof hash: ${afterAudit.tallyProofHash || "(none)"}`,
  `- Published root transactions: ${rootTransactions.length}`,
  ...rootTransactions.map((signature) => `  - ${signature}`),
  `- Final result transaction: ${
    publication.publication?.finalResultSignature || "(not published)"
  }`,
  "",
  "## Public Verifier",
  "",
  "```text",
  (verifier.stdout || "").trim(),
  "```",
  "",
  "## Artifacts",
  "",
  `- Directory: ${artifactDir}`,
  `- Health: ${zkpHealthFile}`,
  `- Audit before: ${join(artifactDir, "audit-before.json")}`,
  `- Audit after: ${auditFile}`,
  `- Publication: ${publicationFile}`,
  `- Receipt: ${receiptFile || "(not captured)"}`,
  `- Public verifier output: ${join(artifactDir, "public-audit-verifier.txt")}`,
  "",
);

const transcriptFile = join(artifactDir, "PHASE7-TRANSCRIPT.md");
writeFileSync(transcriptFile, `${transcriptLines.join("\n")}\n`);

console.log("Phase 7 publication acceptance OK");
console.log(`  artifacts=${artifactDir}`);
console.log(`  transcript=${transcriptFile}`);
console.log(`  publicationStatus=${afterAudit.publicationStatus}`);
console.log(`  rootCommits=${afterAudit.rootCommits.length}`);
console.log(
  `  finalResultTx=${publication.publication?.finalResultSignature || "(not published)"}`,
);
