import assert from "node:assert/strict";
import test from "node:test";

import {
  deriveCollectionStatus,
  normalizeEvidenceConfig,
} from "./run-evidence-collection.mjs";

test("normalizes configured stages and command-line sessions", () => {
  const config = normalizeEvidenceConfig({
    rawConfig: {
      schemaVersion: "civicos-evidence-collection-config-v1",
      outputRoot: "results",
      mobileSessions: ["ios.json"],
      historicalPollCohort: {
        enabled: true,
        backendUrl: "https://backend.example",
        expectedPollCount: 4,
      },
      privacyAudit: {
        enabled: true,
        markerFile: "markers.json",
        targets: [{ label: "service logs", path: "logs" }],
      },
    },
    configDir: "/private/config",
    args: ["--session", "/private/android.json", "--run-faults"],
  });

  assert.deepEqual(config.mobileSessions, [
    "/private/config/ios.json",
    "/private/android.json",
  ]);
  assert.equal(config.historicalPollCohort.enabled, true);
  assert.equal(config.historicalPollCohort.backendUrl, "https://backend.example");
  assert.equal(config.historicalPollCohort.expectedPollCount, 4);
  assert.equal(config.faultTrials.enabled, true);
  assert.equal(config.privacyAudit.markerFile, "/private/config/markers.json");
  assert.deepEqual(config.privacyAudit.targets, [
    { label: "service-logs", path: "/private/config/logs" },
  ]);
  assert.equal(config.outputRoot, "/private/config/results");
});

test("never treats blocked or failed collectors as completed", () => {
  assert.equal(deriveCollectionStatus([], true), "no_stages_requested");
  assert.equal(deriveCollectionStatus([{ status: "completed" }], true), "collectors_completed");
  assert.equal(deriveCollectionStatus([{ status: "blocked" }], true), "collector_incomplete");
  assert.equal(deriveCollectionStatus([{ status: "failed" }], true), "collector_failed");
  assert.equal(deriveCollectionStatus([{ status: "in_progress" }], false), "in_progress");
});

test("rejects unknown config schemas", () => {
  assert.throws(
    () => normalizeEvidenceConfig({ rawConfig: { schemaVersion: "unknown" } }),
    /Unsupported evidence collection config schema/u,
  );
});
