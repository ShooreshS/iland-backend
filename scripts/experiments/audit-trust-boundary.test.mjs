import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";

import {
  normalizeIdentifierCandidate,
  runTrustBoundaryAudit,
} from "./audit-trust-boundary.mjs";

const privateKey = "test-only-pseudonym-key-with-32-bytes";

test("normalizes the same v1 and v2 identifier forms as the mobile contract", () => {
  assert.equal(normalizeIdentifierCandidate("12-34 56<78/90", 1), "1234567890");
  assert.equal(
    normalizeIdentifierCandidate("1990-01-01-0017", 2),
    "SWE:199001010017",
  );
  assert.equal(normalizeIdentifierCandidate("1990-01-01-0018", 2), null);
});

test("classifies raw, reversible, and digest observations without exporting specimens", () => {
  const root = mkdtempSync(resolve(tmpdir(), "civicos-trust-boundary-"));
  const targetDir = resolve(root, "server-logs");
  const outputDir = resolve(root, "output");
  mkdirSync(targetDir, { recursive: true });

  const civilIdentifier = "1234567890";
  const liveFaceBytes = Buffer.from("synthetic-live-face-image-bytes");
  const digest = createHash("sha512").update(civilIdentifier).digest("hex");
  writeFileSync(
    resolve(targetDir, "request.json"),
    JSON.stringify({
      nidnh: digest,
      accidentalCopy: liveFaceBytes.toString("base64"),
    }),
  );
  writeFileSync(
    resolve(root, "candidates.txt"),
    `0000000000\n${civilIdentifier}\n9999999999\n`,
  );
  writeFileSync(resolve(root, "review-evidence.txt"), "re-encoded face matched fixture");

  const protocol = {
    schemaVersion: "civicos-trust-boundary-audit-v1",
    cohortId: "android-release-test",
    build: "test-build",
    commit: "test-commit",
    specimens: [
      {
        specimenId: "civil-id",
        dataClass: "raw-civil-identifier",
        expectation: "device_only_raw",
        value: civilIdentifier,
        representations: ["raw", "sha512_hex"],
      },
      {
        specimenId: "live-face",
        dataClass: "live-face-image",
        expectation: "device_only_raw",
        value: liveFaceBytes.toString("base64"),
        inputEncoding: "base64",
        representations: ["raw", "base64", "sha256_hex"],
      },
    ],
    targets: [
      {
        targetId: "service-logs",
        flowId: "automatic-identity-success",
        side: "server",
        layer: "application-log",
        checkpoint: "immediate",
        path: "server-logs",
      },
    ],
    identifierTrials: [
      {
        trialId: "iran-v1-fixture",
        flowId: "automatic-identity-success",
        normalizationVersion: 1,
        observedNidnh: digest,
        candidatesFile: "candidates.txt",
        candidateSpaceSize: 3,
        completeCandidateSpace: true,
      },
    ],
    reviewFindings: [
      {
        findingId: "reencoded-face-match",
        targetId: "service-logs",
        dataClass: "live-face-image",
        exposureClass: "raw",
        method: "perceptual-image-review",
        evidenceFile: "review-evidence.txt",
        reviewerCodes: ["reviewer-a", "reviewer-b"],
        secondReviewerConfirmed: true,
      },
    ],
  };
  const protocolPath = resolve(root, "protocol.json");
  writeFileSync(protocolPath, JSON.stringify(protocol));

  const report = runTrustBoundaryAudit({
    protocolPath,
    outputDir,
    pseudonymKey: privateKey,
  });
  const civilObservation = report.observations.find((entry) => entry.specimenId === "civil-id");
  const faceObservation = report.observations.find((entry) => entry.specimenId === "live-face");

  assert.equal(civilObservation.highestExposure, "deterministic_digest");
  assert.equal(civilObservation.rawOrReversibleObserved, false);
  assert.equal(civilObservation.expectationMet, true);
  assert.equal(faceObservation.highestExposure, "reversible");
  assert.equal(faceObservation.rawOrReversibleObserved, true);
  assert.equal(faceObservation.expectationMet, false);
  assert.equal(report.identifierReconstruction[0].recovered, true);
  assert.equal(report.identifierReconstruction[0].validCandidatesChecked, 2);
  assert.equal(report.reviewFindings[0].exposureClass, "raw");
  assert.equal(report.reviewFindings[0].secondReviewerConfirmed, true);
  assert.equal(report.automatedRawLocalityGate.status, "failed");

  const exported = [
    readFileSync(resolve(outputDir, "trust-boundary-audit.json"), "utf8"),
    readFileSync(resolve(outputDir, "operator-observation-matrix.csv"), "utf8"),
    readFileSync(resolve(outputDir, "reconstruction-trials.jsonl"), "utf8"),
    readFileSync(resolve(outputDir, "operator-review-findings.jsonl"), "utf8"),
  ].join("\n");
  assert.equal(exported.includes(civilIdentifier), false);
  assert.equal(exported.includes(liveFaceBytes.toString("base64")), false);
  assert.equal(exported.includes("re-encoded face matched fixture"), false);
});
