#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyGroth16WithPinnedCli } from "./groth16-verify.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const backendRoot = resolve(scriptDir, "../..");
const args = process.argv.slice(2);
const sessionPaths = args.flatMap((entry, index) => {
  if (entry === "--session" && args[index + 1]) return [resolve(args[index + 1])];
  if (entry.startsWith("--session=")) return [resolve(entry.slice("--session=".length))];
  return [];
});
const valueFor = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
};
if (sessionPaths.length === 0) {
  throw new Error("Provide at least one mobile export with --session <file>.");
}

const outputDir = resolve(
  valueFor("--output-dir") || resolve(backendRoot, "tmp/experiments/mobile-verification"),
);
const vkeyPath = resolve(
  process.env.CIVICOS_MOBILE_BENCHMARK_VKEY
    || resolve(
      backendRoot,
      "src/services/__fixtures__/groth16-vote/credential_commitment_vote.vkey.json",
    ),
);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const vkeyBytes = readFileSync(vkeyPath);
const vkeyHash = sha256(vkeyBytes);
const vkey = JSON.parse(vkeyBytes.toString("utf8"));
const expectedVerifierKeyHash =
  "edbb91b2e0bf49013ac3c4e214c1101d0b85724c5e818ef53c7e8175a268ec46";
if (vkeyHash !== expectedVerifierKeyHash) {
  throw new Error(`Unexpected mobile verifier key SHA-256: ${vkeyHash}`);
}

const rows = [];
const seenRecordIds = new Set();
let benchmarkResultCount = 0;
let benchmarkFailureCount = 0;
for (const sessionPath of sessionPaths) {
  const sessionBytes = readFileSync(sessionPath);
  const session = JSON.parse(sessionBytes.toString("utf8"));
  if (session.schemaVersion !== "civicos-experiment-session-v1") {
    throw new Error(`Unexpected session schema in ${sessionPath}.`);
  }
  const benchmarkRecords = (session.records || []).filter(
    (record) => record?.workflow === "mobile_zkp_benchmark",
  );
  for (const record of benchmarkRecords) {
    benchmarkResultCount += 1;
    if (record.outcome !== "success") benchmarkFailureCount += 1;
    if (!record.recordId || seenRecordIds.has(record.recordId)) {
      throw new Error(`Missing or duplicate benchmark record id in ${sessionPath}.`);
    }
    seenRecordIds.add(record.recordId);
    const fixture = record.syntheticVerifierFixture;
    const proof = fixture?.groth16Output;
    const publicSignals = fixture?.publicOutputs;
    if (!proof || !Array.isArray(publicSignals) || publicSignals.length === 0) {
      if (record.outcome === "failure") continue;
      throw new Error(`Benchmark record ${record.recordId} has no synthetic verifier fixture.`);
    }
    const proofSha256 = sha256(JSON.stringify(proof));
    const startedAt = performance.now();
    const { accepted, errorClass } = verifyGroth16WithPinnedCli({
      verificationKey: vkey,
      publicSignals,
      proof,
    });
    rows.push({
      schemaVersion: "civicos-mobile-benchmark-verification-v1",
      sessionSha256: sha256(sessionBytes),
      recordId: record.recordId,
      cohort: record.cohort || "unknown",
      sequence: record.trial?.sequence ?? null,
      verifierKeySha256: vkeyHash,
      proofSha256,
      recordedProofHashMatches: proofSha256 === record.output?.sha256,
      accepted,
      verifyMs: Math.round((performance.now() - startedAt) * 1000) / 1000,
      errorClass,
    });
  }
}

if (benchmarkResultCount === 0) {
  throw new Error("No mobile_zkp_benchmark result records were found.");
}
const summary = {
  schemaVersion: "civicos-mobile-benchmark-verification-summary-v1",
  verifiedAt: new Date().toISOString(),
  sessionCount: sessionPaths.length,
  benchmarkResultCount,
  benchmarkFailureCount,
  recordCount: rows.length,
  acceptedCount: rows.filter((row) => row.accepted).length,
  proofHashMatchCount: rows.filter((row) => row.recordedProofHashMatches).length,
  verifierKeySha256: vkeyHash,
};
mkdirSync(outputDir, { recursive: true });
writeFileSync(
  resolve(outputDir, "mobile-benchmark-verification.jsonl"),
  `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`,
  { mode: 0o600 },
);
writeFileSync(
  resolve(outputDir, "mobile-benchmark-verification-summary.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
  { mode: 0o600 },
);
console.log(JSON.stringify(summary, null, 2));
if (
  benchmarkFailureCount > 0
  || summary.acceptedCount !== rows.length
  || summary.proofHashMatchCount !== rows.length
) {
  process.exitCode = 1;
}
