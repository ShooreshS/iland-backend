#!/usr/bin/env node

import { createHash, createHmac } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { Connection, PublicKey, clusterApiUrl } from "@solana/web3.js";
import { createClient } from "@supabase/supabase-js";

import { verifyGroth16WithPinnedCli } from "./groth16-verify.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const backendRoot = resolve(scriptDir, "../..");
const tallyVkeyPath = resolve(
  backendRoot,
  "src/services/__fixtures__/groth16-tally/encrypted_choice_tally.vkey.json",
);
const tallyVkeyBytes = readFileSync(tallyVkeyPath);
const tallyVkeyHash = createHash("sha256").update(tallyVkeyBytes).digest("hex");
const tallyVkey = JSON.parse(tallyVkeyBytes.toString("utf8"));
const bn254ScalarField = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);
const tallyPublicSignalOrder = [
  "pollId",
  "pollPolicyHash",
  "credentialSchemaHash",
  "optionSetHash",
  "optionCount",
  "nullifierRoot",
  "voteCommitmentRoot",
  "encryptedVoteRoot",
  "acceptedVoteCount",
  "optionCountsHash",
];

const loadEnv = (path) => {
  if (!existsSync(path)) return;
  for (const rawLine of readFileSync(path, "utf8").split(/\r?\n/u)) {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/u.exec(rawLine.trim());
    if (!match || process.env[match[1]] !== undefined) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[match[1]] = value;
  }
};
loadEnv(resolve(backendRoot, ".env"));

const required = (name) => {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
};
const backendUrl = required("CIVICOS_EXPERIMENT_BACKEND_URL").replace(/\/+$/u, "");
const pseudonymKey = required("CIVICOS_EXPERIMENT_PSEUDONYM_KEY");
const outputDir = resolve(
  process.env.CIVICOS_EXPERIMENT_OUTPUT_DIR || resolve(backendRoot, "tmp/experiments/five-polls"),
);
const cluster = String(process.env.SOLANA_AUDIT_CLUSTER || "devnet").trim();
if (cluster !== "devnet") throw new Error("The five-poll article cohort must use devnet.");
const connection = new Connection(
  process.env.SOLANA_AUDIT_RPC_URL || clusterApiUrl("devnet"),
  "confirmed",
);
const programId = new PublicKey(
  process.env.SOLANA_AUDIT_PROGRAM_ID || "FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo",
);
const programAccount = await connection.getAccountInfo(programId, "confirmed");
if (!programAccount?.executable) {
  throw new Error(`Configured audit program ${programId.toBase58()} is missing or is not executable.`);
}
const supabase = createClient(required("SUPABASE_URL"), required("SUPABASE_SERVICE_ROLE_KEY"), {
  auth: { autoRefreshToken: false, persistSession: false },
  global: { headers: { "X-Client-Info": "civicos-five-poll-evidence" } },
});

const query = async (table, columns, pollId) => {
  const { data, error } = await supabase.from(table).select(columns).eq("poll_id", pollId);
  if (error) throw error;
  return data || [];
};
const pseudonym = (pollId) =>
  `poll-${createHmac("sha256", pseudonymKey).update(pollId).digest("hex").slice(0, 16)}`;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const encodePublicField = (name, value) => {
  const normalized = String(value).trim();
  if (/^[0-9a-f]{64}$/iu.test(normalized)) {
    return (BigInt(`0x${normalized}`) % bn254ScalarField).toString(10);
  }
  if (/^[0-9]+$/u.test(normalized)) {
    return (BigInt(normalized) % bn254ScalarField).toString(10);
  }
  const digest = createHash("sha256")
    .update("org.civicos.zkp:public-field:v1", "utf8")
    .update("\0", "utf8")
    .update(name, "utf8")
    .update("\0", "utf8")
    .update(normalized, "utf8")
    .digest("hex");
  return (BigInt(`0x${digest}`) % bn254ScalarField).toString(10);
};

let pollIds = String(process.env.CIVICOS_EXPERIMENT_POLL_IDS || "")
  .split(",")
  .map((entry) => entry.trim())
  .filter(Boolean);
if (pollIds.length === 0) {
  const { data, error } = await supabase
    .from("poll_zk_votes")
    .select("poll_id")
    .eq("proof_verification_status", "verified")
    .limit(5000);
  if (error) throw error;
  pollIds = [...new Set((data || []).map((row) => row.poll_id))];
}
if (pollIds.length !== 5) {
  throw new Error(`Expected exactly five poll ids; found ${pollIds.length}. Set CIVICOS_EXPERIMENT_POLL_IDS.`);
}

mkdirSync(outputDir, { recursive: true });
const evidence = [];
const solanaRows = [];

for (const pollId of pollIds) {
  const code = pseudonym(pollId);
  const [{ data: poll, error: pollError }, votes, roots, tallies, events] = await Promise.all([
    supabase
      .from("polls")
      .select("id,status,vote_privacy_mode,result_publication_mode,poll_policy_hash,credential_schema_hash,option_set_hash,created_at,starts_at,ends_at")
      .eq("id", pollId)
      .single(),
    query("poll_zk_votes", "nullifier,proof_verification_status,encrypted_vote_hash,encrypted_vote_commitment,proof_hash,proof_envelope_hash,verifier_key_hash,circuit_id,accepted_at,batch_id", pollId),
    query("poll_roots", "batch_id,nullifier_root,vote_commitment_root,encrypted_vote_root,accepted_count,solana_tx_signature,created_at", pollId),
    query("poll_tally_proofs", "result_hash,tally_proof_hash,tally_public_inputs_hash,tally_verifier_key_hash,tally_circuit_id,nullifier_root,vote_commitment_root,encrypted_vote_root,accepted_count,proof_envelope_json,verified_at", pollId),
    query("poll_audit_events", "event_type,payload_hash,solana_tx_signature,created_at", pollId),
  ]);
  if (pollError) throw pollError;

  const auditResponse = await fetch(`${backendUrl}/polls/${encodeURIComponent(pollId)}/audit`);
  if (!auditResponse.ok) throw new Error(`Public audit fetch failed for ${code}: HTTP ${auditResponse.status}`);
  const audit = await auditResponse.json();
  const temporaryAuditPath = resolve(tmpdir(), `civicos-audit-${process.pid}-${code}.json`);
  writeFileSync(temporaryAuditPath, JSON.stringify(audit));
  const verification = spawnSync(
    process.execPath,
    [resolve(backendRoot, "scripts/verify-public-audit.mjs"), "--audit", temporaryAuditPath],
    { cwd: backendRoot, encoding: "utf8" },
  );
  rmSync(temporaryAuditPath, { force: true });

  const signatures = [
    ...roots.map((row) => row.solana_tx_signature),
    ...events
      .filter((row) => row.event_type === "poll_final_result_published_on_chain")
      .map((row) => row.solana_tx_signature),
  ].filter(Boolean);
  const statuses = signatures.length > 0
    ? (await connection.getSignatureStatuses(signatures, { searchTransactionHistory: true })).value
    : [];
  const transactionChecks = [];
  for (const [index, signature] of signatures.entries()) {
    const status = statuses[index];
    const transaction = await connection.getParsedTransaction(signature, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const accountKeys = transaction?.transaction.message.accountKeys || [];
    const programReferenced = accountKeys.some((entry) => {
      const key = entry && typeof entry === "object" && "pubkey" in entry
        ? entry.pubkey
        : entry;
      return typeof key?.toBase58 === "function"
        && key.toBase58() === programId.toBase58();
    });
    const programInvoked = (transaction?.transaction.message.instructions || [])
      .some((instruction) => instruction.programId?.toBase58() === programId.toBase58());
    const transactionCheck = {
      pollCode: code,
      transactionSignature: signature,
      signatureSha256: sha256(signature),
      found: Boolean(status),
      confirmationStatus: status?.confirmationStatus || null,
      slot: status?.slot || null,
      succeeded: status ? status.err === null : false,
      programId: programId.toBase58(),
      programReferenced,
      programInvoked,
    };
    solanaRows.push(transactionCheck);
    transactionChecks.push(transactionCheck);
  }

  const finalEvents = events.filter((row) => row.event_type === "poll_final_result_published_on_chain");
  const tallyVerificationChecks = [];
  for (const tally of tallies) {
    const envelope = tally.proof_envelope_json;
    const publicInputs = envelope?.publicInputs;
    let verification = { accepted: false, errorClass: "TALLY_FIXTURE_INVALID" };
    try {
      const publicSignals = tallyPublicSignalOrder.map((name) =>
        encodePublicField(name, publicInputs?.[name]));
      verification = tally.tally_verifier_key_hash === tallyVkeyHash
        ? verifyGroth16WithPinnedCli({
          verificationKey: tallyVkey,
          publicSignals,
          proof: envelope?.proof,
        })
        : { accepted: false, errorClass: "VERIFIER_KEY_HASH_MISMATCH" };
    } catch (error) {
      verification = {
        accepted: false,
        errorClass: error instanceof Error ? error.name : "TALLY_VERIFY_FAILED",
      };
    }
    tallyVerificationChecks.push({
      accepted: verification.accepted,
      verifierKeyHashMatches: tally.tally_verifier_key_hash === tallyVkeyHash,
      errorClass: verification.errorClass,
    });
  }
  const uniqueNullifierCount = new Set(votes.map((row) => row.nullifier)).size;
  const allVoteEvidencePresent = votes.every((row) =>
    row.nullifier
    && row.encrypted_vote_hash
    && row.encrypted_vote_commitment
    && row.proof_hash
    && row.proof_envelope_hash
    && row.verifier_key_hash
    && row.circuit_id
    && row.accepted_at);
  const latestRootAcceptedCount = roots.reduce(
    (maximum, row) => Math.max(maximum, Number(row.accepted_count || 0)),
    0,
  );
  const qualified =
    votes.length > 0
    && votes.every((row) => row.proof_verification_status === "verified")
    && allVoteEvidencePresent
    && uniqueNullifierCount === votes.length
    && roots.length > 0
    && roots.every((row) => Boolean(row.solana_tx_signature))
    && latestRootAcceptedCount === votes.length
    && tallies.length > 0
    && tallies.every((row) => Boolean(row.verified_at))
    && tallyVerificationChecks.every((row) => row.accepted)
    && finalEvents.some((row) => Boolean(row.solana_tx_signature))
    && Number(audit.acceptedVoteCount) === votes.length
    && verification.status === 0
    && statuses.every((status) => status?.err === null && Boolean(status.confirmationStatus))
    && transactionChecks.every((entry) => entry.programReferenced && entry.programInvoked);

  evidence.push({
    pollCode: code,
    status: poll.status,
    privacyMode: poll.vote_privacy_mode,
    publicationMode: poll.result_publication_mode,
    createdAt: poll.created_at,
    startsAt: poll.starts_at,
    endsAt: poll.ends_at,
    acceptedVoteCount: votes.length,
    allVotesVerified: votes.every((row) => row.proof_verification_status === "verified"),
    allVoteEvidencePresent,
    uniqueNullifierCount,
    allNullifiersUniqueWithinPoll: uniqueNullifierCount === votes.length,
    circuitIds: [...new Set(votes.map((row) => row.circuit_id))],
    verifierKeyHashes: [...new Set(votes.map((row) => row.verifier_key_hash))],
    voteRecordHashes: votes.map((row) => ({
      encryptedVoteHash: row.encrypted_vote_hash,
      encryptedVoteCommitment: row.encrypted_vote_commitment,
      proofHash: row.proof_hash,
      proofEnvelopeHash: row.proof_envelope_hash,
      acceptedAt: row.accepted_at,
      batchCode: row.batch_id ? sha256(row.batch_id).slice(0, 16) : null,
    })),
    roots: roots.map((row) => ({
      batchCode: sha256(row.batch_id).slice(0, 16),
      acceptedCount: row.accepted_count,
      nullifierRoot: row.nullifier_root,
      voteCommitmentRoot: row.vote_commitment_root,
      encryptedVoteRoot: row.encrypted_vote_root,
      signatureSha256: row.solana_tx_signature ? sha256(row.solana_tx_signature) : null,
      createdAt: row.created_at,
    })),
    tallies: tallies.map(({ proof_envelope_json: _proofEnvelope, ...row }, index) => ({
      ...row,
      verifierAccepted: tallyVerificationChecks[index]?.accepted === true,
      verifierKeyHashMatches:
        tallyVerificationChecks[index]?.verifierKeyHashMatches === true,
      verifierErrorClass: tallyVerificationChecks[index]?.errorClass || null,
    })),
    finalPublicationCount: finalEvents.length,
    publicAudit: {
      acceptedVoteCount: audit.acceptedVoteCount,
      resultHash: audit.resultHash,
      tallyProofHash: audit.tallyProofHash || null,
      tallyPublicInputsHash: audit.tallyPublicInputsHash || null,
    },
    publicAuditVerifierPassed: verification.status === 0,
    qualified,
  });
}

const summary = {
  schemaVersion: "civicos-historical-five-poll-evidence-v1",
  collectedAt: new Date().toISOString(),
  cluster,
  programId: programId.toBase58(),
  examined: evidence.length,
  qualified: evidence.filter((entry) => entry.qualified).length,
  acceptedVoteCount: evidence.reduce((sum, entry) => sum + entry.acceptedVoteCount, 0),
  rootPublicationCount: evidence.reduce((sum, entry) => sum + entry.roots.length, 0),
  tallyVerificationCount: evidence.reduce((sum, entry) => sum + entry.tallies.length, 0),
  finalPublicationCount: evidence.reduce((sum, entry) => sum + entry.finalPublicationCount, 0),
  polls: evidence,
};
writeFileSync(resolve(outputDir, "historical-five-poll-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
writeFileSync(resolve(outputDir, "historical-five-poll-solana-checks.jsonl"), `${solanaRows.map((row) => JSON.stringify(row)).join("\n")}\n`, { mode: 0o600 });
console.log(JSON.stringify({ ...summary, polls: evidence.map(({ pollCode, qualified, acceptedVoteCount }) => ({ pollCode, qualified, acceptedVoteCount })) }, null, 2));
if (summary.qualified !== 5) process.exitCode = 1;
