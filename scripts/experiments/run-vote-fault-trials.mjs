#!/usr/bin/env node

import { createHash, createHmac } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createClient } from "@supabase/supabase-js";

const required = (name) => {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
};
if (process.env.CIVICOS_EXPERIMENT_CONFIRM_ISOLATED !== "true") {
  throw new Error("Set CIVICOS_EXPERIMENT_CONFIRM_ISOLATED=true after confirming this is an isolated test database.");
}

const baseUrl = required("CIVICOS_FAULT_BASE_URL").replace(/\/+$/u, "");
const pollId = required("CIVICOS_FAULT_POLL_ID");
const bearerToken = required("CIVICOS_FAULT_BEARER_TOKEN");
const payloadPath = resolve(required("CIVICOS_FAULT_VALID_PAYLOAD_FILE"));
const uniquePayloadsPath = resolve(required("CIVICOS_FAULT_UNIQUE_PAYLOADS_FILE"));
const pseudonymKey = required("CIVICOS_EXPERIMENT_PSEUDONYM_KEY");
const trials = Number(process.env.CIVICOS_FAULT_TRIALS || 100);
if (!Number.isInteger(trials) || trials < 1 || trials > 1000) {
  throw new Error("CIVICOS_FAULT_TRIALS must be an integer from 1 through 1000.");
}
const outputDir = resolve(process.env.CIVICOS_EXPERIMENT_OUTPUT_DIR || "tmp/experiments/faults");
const payload = JSON.parse(readFileSync(payloadPath, "utf8"));
const uniquePayloads = JSON.parse(readFileSync(uniquePayloadsPath, "utf8"));
if (!Array.isArray(uniquePayloads) || uniquePayloads.length < trials * 4) {
  throw new Error(`CIVICOS_FAULT_UNIQUE_PAYLOADS_FILE must contain at least ${trials * 4} unused valid payloads.`);
}
const supabase = createClient(required("SUPABASE_URL"), required("SUPABASE_SERVICE_ROLE_KEY"), {
  auth: { autoRefreshToken: false, persistSession: false },
});
const pollCode = `poll-${createHmac("sha256", pseudonymKey).update(pollId).digest("hex").slice(0, 16)}`;
const clone = (value) => structuredClone(value);
const flipHex = (value) => `${value.startsWith("0") ? "1" : "0"}${value.slice(1)}`;
const proof = (value) => value.privacy.proof.proof;
const publicInputs = (value) => value.privacy.proof.publicInputs;

const mutations = {
  mutated_groth16_coordinate(value) {
    const next = clone(value);
    proof(next).pi_a[0] = proof(next).pi_a[0] === "1" ? "2" : "1";
    return next;
  },
  mismatched_poll_policy(value) {
    const next = clone(value);
    publicInputs(next).pollPolicyHash = flipHex(publicInputs(next).pollPolicyHash);
    return next;
  },
  mismatched_option_set(value) {
    const next = clone(value);
    publicInputs(next).optionSetHash = flipHex(publicInputs(next).optionSetHash);
    return next;
  },
  mismatched_vote_commitment(value) {
    const next = clone(value);
    publicInputs(next).voteCommitment = flipHex(publicInputs(next).voteCommitment);
    return next;
  },
  stale_root(value) {
    const next = clone(value);
    publicInputs(next).credentialRoot = "01".repeat(32);
    return next;
  },
  ciphertext_mutation(value) {
    const next = clone(value);
    const current = String(next.encryptedVote.ciphertext);
    next.encryptedVote.ciphertext = `${current.startsWith("A") ? "B" : "A"}${current.slice(1)}`;
    return next;
  },
};

const countRows = async () => {
  const { count, error } = await supabase
    .from("poll_zk_votes")
    .select("id", { count: "exact", head: true })
    .eq("poll_id", pollId);
  if (error) throw error;
  return count || 0;
};
const send = async (body, runId) => {
  const startedAt = performance.now();
  try {
    const response = await fetch(`${baseUrl}/polls/${encodeURIComponent(pollId)}/votes`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${bearerToken}`,
        "Content-Type": "application/json",
        "X-CivicOS-Experiment-Run": runId,
      },
      body: JSON.stringify(body),
    });
    const responseBody = await response.json().catch(() => null);
    return {
      httpStatus: response.status,
      responseClass: responseBody?.errorCode || (responseBody?.success ? "ACCEPTED" : "UNKNOWN"),
      accepted: responseBody?.success === true,
      durationMs: Math.round((performance.now() - startedAt) * 1000) / 1000,
      transportClass: "completed",
    };
  } catch (error) {
    return {
      httpStatus: null,
      responseClass: error instanceof Error ? error.name : "REQUEST_FAILED",
      accepted: false,
      durationMs: Math.round((performance.now() - startedAt) * 1000) / 1000,
      transportClass: "failed",
    };
  }
};

const rows = [];
for (const [faultClass, mutate] of Object.entries(mutations)) {
  for (let trial = 1; trial <= trials; trial += 1) {
    const before = await countRows();
    const runId = `fault-${createHash("sha256").update(`${faultClass}:${trial}:${Date.now()}`).digest("hex").slice(0, 20)}`;
    const observed = await send(mutate(payload), runId);
    const after = await countRows();
    rows.push({
      faultClass,
      trial,
      expectedClass: "rejected_without_insert",
      ...observed,
      rowDelta: after - before,
      invariantPassed: observed.accepted === false && after === before,
    });
  }
}

for (let trial = 1; trial <= trials; trial += 1) {
  const before = await countRows();
  const first = await send(uniquePayloads[trial - 1], `replay-first-${trial}-${Date.now().toString(36)}`);
  const second = await send(uniquePayloads[trial - 1], `replay-second-${trial}-${Date.now().toString(36)}`);
  const after = await countRows();
  rows.push({
    faultClass: "reused_nullifier",
    trial,
    concurrency: 1,
    expectedClass: "one_insert_then_duplicate_rejection",
    httpStatus: second.httpStatus,
    responseClass: second.responseClass,
    accepted: first.accepted && !second.accepted,
    durationMs: first.durationMs + second.durationMs,
    transportClass: first.transportClass === "completed" && second.transportClass === "completed" ? "completed" : "partial",
    rowDelta: after - before,
    invariantPassed: after - before === 1 && first.accepted && !second.accepted,
  });
}

for (const [concurrencyIndex, concurrency] of [2, 8, 32].entries()) {
  for (let trial = 1; trial <= trials; trial += 1) {
    const before = await countRows();
    const racePayload = uniquePayloads[trials + concurrencyIndex * trials + trial - 1];
    const results = await Promise.all(
      Array.from({ length: concurrency }, (_, index) =>
        send(racePayload, `race-${concurrency}-${trial}-${index}-${Date.now().toString(36)}`)),
    );
    const after = await countRows();
    const acceptedResponses = results.filter((entry) => entry.accepted).length;
    rows.push({
      faultClass: "nullifier_race",
      trial,
      concurrency,
      expectedClass: "exactly_one_insert",
      httpStatus: null,
      responseClass: "MIXED",
      accepted: acceptedResponses === 1,
      durationMs: Math.max(...results.map((entry) => entry.durationMs)),
      transportClass: results.every((entry) => entry.transportClass === "completed") ? "completed" : "partial",
      rowDelta: after - before,
      invariantPassed: after - before === 1 && acceptedResponses === 1,
    });
  }
}

mkdirSync(outputDir, { recursive: true });
const columns = [
  "faultClass", "trial", "concurrency", "expectedClass", "httpStatus", "responseClass",
  "accepted", "durationMs", "transportClass", "rowDelta", "invariantPassed",
];
const csv = [
  columns.join(","),
  ...rows.map((row) => columns.map((key) => JSON.stringify(row[key] ?? "")).join(",")),
].join("\n");
writeFileSync(resolve(outputDir, "fault-trials.csv"), `${csv}\n`, { mode: 0o600 });
const summary = {
  schemaVersion: "civicos-fault-trials-v1",
  measuredAt: new Date().toISOString(),
  pollCode,
  requestedTrialsPerClass: trials,
  observations: rows.length,
  invariantFailures: rows.filter((row) => !row.invariantPassed).length,
  byClass: Object.fromEntries(
    [...new Set(rows.map((row) => row.faultClass))].map((faultClass) => {
      const group = rows.filter((row) => row.faultClass === faultClass);
      return [faultClass, { observations: group.length, passed: group.filter((row) => row.invariantPassed).length }];
    }),
  ),
};
writeFileSync(resolve(outputDir, "fault-invariants.json"), `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify(summary, null, 2));
if (summary.invariantFailures > 0) process.exitCode = 1;
