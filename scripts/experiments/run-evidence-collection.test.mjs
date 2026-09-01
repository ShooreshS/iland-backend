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
      historicalFivePolls: { enabled: true },
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
  assert.equal(config.historicalFivePolls.enabled, true);
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
