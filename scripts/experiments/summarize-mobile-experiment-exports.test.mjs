import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const summarizerPath = resolve(scriptDir, "summarize-mobile-experiment-exports.mjs");
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

test("exports privacy-safe mobile trust-boundary observations", () => {
  const fixtureDir = mkdtempSync(resolve(tmpdir(), "civicos-mobile-summary-"));
  const sessionPath = resolve(fixtureDir, "session.json");
  const outputDir = resolve(fixtureDir, "summary");
  const sessionContent = {
    schemaVersion: "civicos-experiment-session-v1",
    sessionId: "session-test-001",
    state: "complete",
    createdAt: "2026-09-19T08:00:00.000Z",
    updatedAt: "2026-09-19T08:01:00.000Z",
    app: {
      version: "0.0.889",
      build: "88915",
      referenceBuild: "0.0.889 (88915)",
      runtime: "native",
    },
    device: { platform: "android", model: "test-device" },
    configuration: { deviceRole: "mid", networkProfile: "wifi" },
    records: [{
      recordId: "record-test-001",
      recordedAt: "2026-09-19T08:00:30.000Z",
      experimentId: "E6-TB",
      workflow: "identity_onboarding",
      outcome: "success",
      stages: [{
        stage: "identity_transfer_boundary_prepared",
        outcome: "success",
        timingClock: "performance.now",
        metadata: {
          transferClass: "automatic_derived_outputs",
          protocolFieldCount: 4,
          nestedFieldCount: 7,
          unexpectedFieldCount: 0,
          sourceMediaIncluded: false,
          directCivilValueIncluded: false,
          digestIncluded: true,
          livenessDecisionIncluded: true,
          likenessDecisionIncluded: true,
          likenessScoreIncluded: true,
          humanReviewReferenceIncluded: false,
        },
      }],
    }],
  };
  const serializedContent = JSON.stringify(sessionContent, null, 2);
  const session = {
    ...sessionContent,
    export: {
      exportedAt: "2026-09-19T08:02:00.000Z",
      contentSha256: sha256(serializedContent),
    },
  };
  writeFileSync(sessionPath, `${JSON.stringify(session, null, 2)}\n`, { mode: 0o600 });

  const result = spawnSync(process.execPath, [
    summarizerPath,
    "--session",
    sessionPath,
    "--output-dir",
    outputDir,
  ], { encoding: "utf8" });

  assert.equal(result.status, 0, result.stderr);
  const summary = JSON.parse(readFileSync(
    resolve(outputDir, "mobile-session-inventory.json"),
    "utf8",
  ));
  assert.equal(summary.trustBoundaryObservationCount, 1);
  assert.equal(summary.e6.automaticDerivedOutputObservations, 1);
  assert.equal(summary.e6.humanReviewReferenceObservations, 0);
  assert.equal(summary.e6.observationsWithSourceMedia, 0);
  assert.equal(summary.e6.observationsWithDirectCivilValue, 0);
  assert.equal(summary.e6.observationsWithUnexpectedFields, 0);

  const observation = JSON.parse(readFileSync(
    resolve(outputDir, "mobile-trust-boundary-observations.jsonl"),
    "utf8",
  ).trim());
  assert.equal(observation.transferClass, "automatic_derived_outputs");
  assert.equal(observation.protocolFieldCount, 4);
  assert.equal(observation.nestedFieldCount, 7);
  assert.equal(observation.sourceMediaIncluded, false);
  assert.equal(observation.directCivilValueIncluded, false);
  assert.equal(observation.digestIncluded, true);
  assert.equal("nidnh" in observation, false);
  assert.equal("identity" in observation, false);
});
