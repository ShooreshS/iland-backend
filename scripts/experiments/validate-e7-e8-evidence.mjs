#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";

const args = process.argv.slice(2);
const valueFor = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
};
const ceremonyPath = valueFor("--ceremony");
const reviewPath = valueFor("--review");
if (!ceremonyPath || !reviewPath) {
  throw new Error("Usage: node validate-e7-e8-evidence.mjs --ceremony ceremony.json --review independent-review.json");
}
const readJson = (path) => JSON.parse(readFileSync(resolve(path), "utf8"));
const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const checks = [];
const check = (condition, label) => checks.push({ label, passed: Boolean(condition) });
const isSha256 = (value) => /^[0-9a-f]{64}$/u.test(String(value || ""));
const checkArtifact = (baseDir, artifact, label) => {
  const path = resolve(baseDir, String(artifact?.path || ""));
  const isFile = existsSync(path) && statSync(path).isFile();
  check(isFile, `${label} exists as a file`);
  check(isSha256(artifact?.sha256), `${label} has a SHA-256 value`);
  if (isFile && isSha256(artifact?.sha256)) {
    check(sha256File(path) === artifact.sha256, `${label} SHA-256 matches`);
  }
};

const ceremonyFile = resolve(ceremonyPath);
const ceremony = readJson(ceremonyFile);
check(ceremony.schemaVersion === "civicos-e7-ceremony-evidence-v1", "E7 schema version");
check(Array.isArray(ceremony.contributors) && ceremony.contributors.length >= 3, "E7 has at least three contributors");
check(ceremony.contributors?.every((entry) =>
  entry.independent === true
  && entry.contributorCode
  && entry.independenceGroup
  && isSha256(entry.attestationSha256)
  && isSha256(entry.contributionReceiptSha256)), "E7 contributors have coded independence declarations, attestations, and receipts");
check(new Set(ceremony.contributors?.map((entry) => entry.independenceGroup)).size >= 3, "E7 contributors represent at least three independence groups");
check(Array.isArray(ceremony.circuits) && ceremony.circuits.length >= 2, "E7 includes both circuits");
check(ceremony.circuits?.every((entry) =>
  entry.circuitId
  && entry.compilerVersion
  && entry.containerDigest
  && Number.isInteger(entry.constraintCount)
  && entry.constraintCount > 0
  && isSha256(entry.sourceSha256)
  && isSha256(entry.dependencyLockSha256)
  && isSha256(entry.r1csSha256)
  && isSha256(entry.initialParametersSha256)
  && isSha256(entry.finalProvingKeySha256)
  && isSha256(entry.finalVerificationKeySha256)
  && isSha256(entry.verificationOutputSha256)), "E7 circuit records include build metadata and all required hashes");
check(Array.isArray(ceremony.artifacts) && ceremony.artifacts.length > 0, "E7 artifact manifest is present");
for (const [index, artifact] of (ceremony.artifacts || []).entries()) {
  checkArtifact(dirname(ceremonyFile), artifact, `E7 artifact ${index + 1}`);
}
check(Boolean(ceremony.publicRandomness?.announcementUri), "E7 public randomness announcement is recorded");
check(isSha256(ceremony.publicRandomness?.valueSha256), "E7 public randomness value hash is recorded");
check(Boolean(ceremony.releaseTag), "E7 signed release tag is recorded");
check(Boolean(ceremony.verificationCommand), "E7 verification command is recorded");

const reviewFile = resolve(reviewPath);
const review = readJson(reviewFile);
check(review.schemaVersion === "civicos-e8-independent-review-v1", "E8 schema version");
check(review.reviewer?.independent === true
  && review.reviewer?.reviewerCode
  && review.reviewer?.conflictsDeclared === true
  && isSha256(review.reviewer?.attestationSha256), "E8 reviewer independence, conflicts, and attestation are recorded");
check(Boolean(review.affectedRevision), "E8 affected revision is recorded");
check(Array.isArray(review.scope) && review.scope.length >= 10, "E8 scope covers the ten registered review areas");
check(Array.isArray(review.findings), "E8 findings are recorded");
check(review.findings?.every((entry) =>
  entry.findingCode
  && ["resolved", "accepted_risk", "open", "disputed", "not_applicable"].includes(entry.status)
  && ["critical", "high", "medium", "low", "informational"].includes(entry.severity)
  && entry.disposition
  && entry.affectedRevision
  && Object.hasOwn(entry, "residualRisk")
  && (entry.status !== "resolved" || (entry.fixCommit && isSha256(entry.retestEvidenceSha256)))), "E8 findings have traceable dispositions and resolved findings have retest evidence");
check(!review.findings?.some((entry) => ["critical", "high"].includes(entry.severity) && entry.status !== "resolved"), "E8 has no unresolved high-severity finding");
check(Array.isArray(review.artifacts) && review.artifacts.length > 0, "E8 report artifact manifest is present");
for (const [index, artifact] of (review.artifacts || []).entries()) {
  checkArtifact(dirname(reviewFile), artifact, `E8 artifact ${index + 1}`);
}

const report = {
  schemaVersion: "civicos-e7-e8-validation-v1",
  checkedAt: new Date().toISOString(),
  status: checks.every((entry) => entry.passed) ? "passed" : "failed",
  checks,
};
console.log(JSON.stringify(report, null, 2));
if (report.status !== "passed") process.exitCode = 1;
