#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const valuesFor = (name) => args.flatMap((entry, index) => {
  if (entry === name && args[index + 1]) return [args[index + 1]];
  if (entry.startsWith(`${name}=`)) return [entry.slice(name.length + 1)];
  return [];
});
const valueFor = (name) => {
  const index = args.indexOf(name);
  if (index >= 0) return args[index + 1] || null;
  const inline = args.find((entry) => entry.startsWith(`${name}=`));
  return inline ? inline.slice(name.length + 1) : null;
};
const sessionPaths = valuesFor("--session").map((path) => resolve(path));
if (sessionPaths.length === 0) {
  throw new Error("Provide at least one mobile export with --session <file>.");
}
const outputDir = resolve(valueFor("--output-dir") || "tmp/experiments/mobile-inventory");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const finiteNumber = (value) => Number.isFinite(value) ? value : null;
const integer = (value) => Number.isInteger(value) ? value : null;
const stringOrNull = (value) => typeof value === "string" && value.length > 0 ? value : null;
const rounded = (value) => Math.round(value * 1000) / 1000;
const median = (sorted) => sorted.length % 2 === 0
  ? (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2
  : sorted[Math.floor(sorted.length / 2)];
const nearestRank = (sorted, probability) =>
  sorted[Math.max(0, Math.ceil(probability * sorted.length) - 1)];
const seededRandom = (seedMaterial) => {
  let state = Number.parseInt(sha256(seedMaterial).slice(0, 8), 16) >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
};
const metricSummary = (values) => {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (sorted.length === 0) return null;
  const mean = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  const sampleStdDev = sorted.length > 1
    ? Math.sqrt(
      sorted.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (sorted.length - 1),
    )
    : null;
  const random = seededRandom(JSON.stringify(sorted));
  const bootstrapMeans = [];
  const bootstrapMedians = [];
  for (let repetition = 0; repetition < 10000; repetition += 1) {
    const sample = Array.from(
      { length: sorted.length },
      () => sorted[Math.floor(random() * sorted.length)],
    ).sort((a, b) => a - b);
    bootstrapMeans.push(sample.reduce((sum, value) => sum + value, 0) / sample.length);
    bootstrapMedians.push(median(sample));
  }
  bootstrapMeans.sort((a, b) => a - b);
  bootstrapMedians.sort((a, b) => a - b);
  return {
    n: sorted.length,
    min: rounded(sorted[0]),
    median: rounded(median(sorted)),
    mean: rounded(mean),
    sampleStdDev: sampleStdDev === null ? null : rounded(sampleStdDev),
    p50NearestRank: rounded(nearestRank(sorted, 0.5)),
    p95NearestRank: rounded(nearestRank(sorted, 0.95)),
    max: rounded(sorted[sorted.length - 1]),
    bootstrap95: {
      repetitions: 10000,
      method: "percentile_nearest_rank",
      median: {
        lower: rounded(nearestRank(bootstrapMedians, 0.025)),
        upper: rounded(nearestRank(bootstrapMedians, 0.975)),
      },
      mean: {
        lower: rounded(nearestRank(bootstrapMeans, 0.025)),
        upper: rounded(nearestRank(bootstrapMeans, 0.975)),
      },
    },
  };
};
const csvValue = (value) => JSON.stringify(value ?? "");
const countBy = (values, selector) => Object.fromEntries(
  [...new Set(values.map(selector))].sort().map((key) => [
    key,
    values.filter((value) => selector(value) === key).length,
  ]),
);

const sessions = [];
const recordRows = [];
const stageRows = [];
const payloadRows = [];
const proofRows = [];
const memoryRows = [];
const seenRecordIds = new Set();

for (const sessionPath of sessionPaths) {
  const bytes = readFileSync(sessionPath);
  const session = JSON.parse(bytes.toString("utf8"));
  if (session.schemaVersion !== "civicos-experiment-session-v1") {
    throw new Error(`Unexpected session schema in ${sessionPath}.`);
  }
  if (!session.sessionId || !Array.isArray(session.records)) {
    throw new Error(`Session id or records are missing in ${sessionPath}.`);
  }
  const sessionSha256 = sha256(bytes);
  const { export: exportEnvelope, ...sessionContent } = session;
  const computedExportContentSha256 = sha256(JSON.stringify(sessionContent, null, 2));
  if (
    exportEnvelope?.contentSha256
    && exportEnvelope.contentSha256 !== computedExportContentSha256
  ) {
    throw new Error(`Export content SHA-256 mismatch in ${sessionPath}.`);
  }
  sessions.push({
    sessionId: session.sessionId,
    sourceSha256: sessionSha256,
    sourceBytes: bytes.length,
    state: stringOrNull(session.state),
    createdAt: stringOrNull(session.createdAt),
    updatedAt: stringOrNull(session.updatedAt),
    exportedAt: stringOrNull(exportEnvelope?.exportedAt),
    exportContentSha256: stringOrNull(exportEnvelope?.contentSha256),
    computedExportContentSha256,
    exportContentHashMatches: exportEnvelope?.contentSha256
      ? exportEnvelope.contentSha256 === computedExportContentSha256
      : null,
    appVersion: stringOrNull(session.app?.version),
    appBuild: stringOrNull(session.app?.build),
    referenceBuild: stringOrNull(session.app?.referenceBuild),
    runtime: stringOrNull(session.app?.runtime),
    platform: stringOrNull(session.device?.platform),
    model: stringOrNull(session.device?.model),
    deviceRole: stringOrNull(session.configuration?.deviceRole),
    networkProfile: stringOrNull(session.configuration?.networkProfile),
    cohortCode: stringOrNull(session.configuration?.cohortCode),
    isPilot: session.configuration?.isPilot === true,
    recordCount: session.records.length,
    missingMetadataCount: Array.isArray(session.missingMetadata)
      ? session.missingMetadata.length
      : null,
  });

  for (const record of session.records) {
    if (!record?.recordId || seenRecordIds.has(record.recordId)) {
      throw new Error(`Missing or duplicate record id in ${sessionPath}.`);
    }
    seenRecordIds.add(record.recordId);
    const workflow = stringOrNull(record.workflow) || "unknown";
    const row = {
      schemaVersion: "civicos-mobile-experiment-record-index-v1",
      sessionId: session.sessionId,
      sessionSha256,
      recordId: record.recordId,
      recordedAt: stringOrNull(record.recordedAt),
      experimentId: stringOrNull(record.experimentId),
      workflow,
      cohort: stringOrNull(record.cohort),
      runId: stringOrNull(record.runId),
      outcome: stringOrNull(record.outcome),
      errorClass: stringOrNull(record.errorClass),
      durationMs: finiteNumber(record.durationMs),
      stageCount: Array.isArray(record.stages) ? record.stages.length : 0,
    };
    if (workflow === "identity_onboarding") {
      Object.assign(row, {
        profileClass: stringOrNull(record.profileClass),
        demoMode: record.demoMode === true,
        cleanupMode: stringOrNull(record.cleanupMode),
      });
    }
    if (workflow === "vote_participation") {
      Object.assign(row, {
        accepted: record.result?.accepted === true,
        receiptPresent: record.result?.receiptPresent === true,
        receiptFingerprint: stringOrNull(record.result?.receiptFingerprint),
        responseClass: stringOrNull(record.result?.responseClass),
        verifierStatus: stringOrNull(record.result?.verifierStatus),
        networkProfile: stringOrNull(record.metadata?.networkProfile),
        feeMode: stringOrNull(record.metadata?.feeMode),
        privacyMode: stringOrNull(record.metadata?.privacyMode),
      });
    }
    if (workflow === "audit_receipt_inclusion") {
      Object.assign(row, {
        inclusionFound: record.result?.inclusionFound === true,
        responseClass: stringOrNull(record.result?.responseClass),
        matchingLeafCount: integer(record.result?.matchingLeafCount),
        proofStepCount: integer(record.result?.proofStepCount),
        rootPresent: record.result?.rootPresent === true,
        receiptFingerprint: stringOrNull(record.metadata?.receiptFingerprint),
        networkProfile: stringOrNull(record.metadata?.networkProfile),
      });
    }
    if (workflow === "runtime_privacy_cleanup") {
      Object.assign(row, {
        fileCandidates: integer(record.fileCandidates),
        fileDeleteFailures: integer(record.fileDeleteFailures),
        storageTasks: integer(record.storageTasks),
        storageTaskFailures: integer(record.storageTaskFailures),
      });
    }
    if (workflow === "mobile_zkp_benchmark") {
      const proofRow = {
        schemaVersion: "civicos-mobile-proof-run-v1",
        sessionId: session.sessionId,
        sessionSha256,
        recordId: record.recordId,
        attemptRecordId: stringOrNull(record.attemptRecordId),
        suiteRunId: stringOrNull(record.suiteRunId),
        cohort: stringOrNull(record.cohort),
        trialType: stringOrNull(record.trial?.type),
        sequence: integer(record.trial?.sequence),
        outcome: stringOrNull(record.outcome),
        errorClass: stringOrNull(record.errorClass),
        artifactLoadMs: finiteNumber(record.timingsMs?.artifactLoadMs),
        witnessBuildMs: finiteNumber(record.timingsMs?.witnessBuildMs),
        proveMs: finiteNumber(record.timingsMs?.proveMs),
        totalMs: finiteNumber(record.timingsMs?.totalMs),
        proofJsonBytes: integer(record.output?.jsonBytes),
        proofSha256: stringOrNull(record.output?.sha256),
        hasGroth16Shape: record.output?.hasGroth16Shape === true,
        peakResidentBytes: integer(record.memory?.peak?.peakResidentBytes),
        peakPhysicalFootprintBytes: integer(record.memory?.peak?.peakPhysicalFootprintBytes),
        peakTotalPssBytes: integer(record.memory?.peak?.peakTotalPssBytes),
        peakSampleCount: integer(record.memory?.peak?.sampleCount),
        peakSamplerDurationMs: finiteNumber(record.memory?.peak?.durationMs),
        settleDelayMs: finiteNumber(record.memory?.settleDelayMs),
        thermalStateBefore: stringOrNull(record.deviceCondition?.before?.thermalState),
        thermalStateAfter: stringOrNull(record.deviceCondition?.after?.thermalState),
        batteryPercentBefore: finiteNumber(record.deviceCondition?.before?.batteryPercent),
        batteryPercentAfter: finiteNumber(record.deviceCondition?.after?.batteryPercent),
        lowPowerModeBefore: record.deviceCondition?.before?.lowPowerMode === true,
        circuitId: stringOrNull(record.circuit?.circuitId),
        proverVersion: stringOrNull(record.circuit?.proverVersion),
        artifactVersion: stringOrNull(record.artifact?.version),
        artifactManifestHash: stringOrNull(record.artifact?.artifactManifestHash),
        verifierKeyHash: stringOrNull(record.artifact?.verifierKeyHash),
      };
      proofRows.push(proofRow);
      memoryRows.push({
        sessionId: session.sessionId,
        recordId: record.recordId,
        cohort: stringOrNull(record.cohort),
        sequence: integer(record.trial?.sequence),
        beforeResidentBytes: integer(record.memory?.before?.residentBytes),
        beforePhysicalFootprintBytes: integer(record.memory?.before?.physicalFootprintBytes),
        beforeProofResidentBytes: integer(record.memory?.beforeProof?.residentBytes),
        beforeProofPhysicalFootprintBytes: integer(record.memory?.beforeProof?.physicalFootprintBytes),
        peakResidentBytes: integer(record.memory?.peak?.peakResidentBytes),
        peakPhysicalFootprintBytes: integer(record.memory?.peak?.peakPhysicalFootprintBytes),
        peakTotalPssBytes: integer(record.memory?.peak?.peakTotalPssBytes),
        peakSampleCount: integer(record.memory?.peak?.sampleCount),
        afterProofResidentBytes: integer(record.memory?.afterProof?.residentBytes),
        afterProofPhysicalFootprintBytes: integer(record.memory?.afterProof?.physicalFootprintBytes),
        afterSettleResidentBytes: integer(record.memory?.afterSettle?.residentBytes),
        afterSettlePhysicalFootprintBytes: integer(record.memory?.afterSettle?.physicalFootprintBytes),
        settleDelayMs: finiteNumber(record.memory?.settleDelayMs),
      });
    }
    recordRows.push(row);

    for (const [sequence, stage] of (record.stages || []).entries()) {
      const stageRow = {
        schemaVersion: "civicos-mobile-experiment-stage-observation-v1",
        sessionId: session.sessionId,
        sessionSha256,
        recordId: record.recordId,
        runId: stringOrNull(record.runId),
        experimentId: stringOrNull(record.experimentId),
        workflow,
        cohort: stringOrNull(record.cohort),
        sequence: sequence + 1,
        stage: stringOrNull(stage?.stage) || "unknown",
        outcome: stringOrNull(stage?.outcome),
        errorClass: stringOrNull(stage?.errorClass),
        durationMs: finiteNumber(stage?.durationMs),
        timingClock: stringOrNull(stage?.timingClock),
      };
      stageRows.push(stageRow);
      if (["request_serialization", "application_payload_observation"].includes(stageRow.stage)) {
        payloadRows.push({
          schemaVersion: "civicos-mobile-application-payload-observation-v1",
          ...stageRow,
          compactJsonUtf8Bytes: integer(stage?.compactJsonUtf8Bytes),
          zkpEnvelopeUtf8Bytes: integer(stage?.zkpEnvelopeUtf8Bytes),
          zkpOutputUtf8Bytes: integer(stage?.zkpOutputUtf8Bytes),
          publicInputEnvelopeUtf8Bytes: integer(stage?.publicInputEnvelopeUtf8Bytes),
          encryptedEnvelopeUtf8Bytes: integer(stage?.encryptedEnvelopeUtf8Bytes),
          receiptCommitmentUtf8Bytes: integer(stage?.receiptCommitmentUtf8Bytes),
          requestBodyUtf8Bytes: integer(stage?.requestBodyUtf8Bytes),
          responseBodyUtf8Bytes: integer(stage?.responseBodyUtf8Bytes),
          httpStatus: integer(stage?.httpStatus),
        });
      }
    }
  }
}

const workflow = (name) => recordRows.filter((row) => row.workflow === name);
const onboardingRows = workflow("identity_onboarding");
const voteRows = workflow("vote_participation");
const inclusionRows = workflow("audit_receipt_inclusion");
const cleanupRows = workflow("runtime_privacy_cleanup");
const exportPrivacyRows = workflow("experiment_export_privacy_validation");
const proofCohorts = Object.fromEntries(
  [...new Set(proofRows.map((row) => row.cohort || "unspecified"))].sort().map((cohort) => {
    const rows = proofRows.filter((row) => (row.cohort || "unspecified") === cohort);
    const successes = rows.filter((row) => row.outcome === "success");
    return [cohort, {
      attempted: rows.length,
      completed: successes.length,
      failures: rows.length - successes.length,
      artifactLoadMs: metricSummary(successes.map((row) => row.artifactLoadMs)),
      witnessBuildMs: metricSummary(successes.map((row) => row.witnessBuildMs)),
      proveMs: metricSummary(successes.map((row) => row.proveMs)),
      totalMs: metricSummary(successes.map((row) => row.totalMs)),
      proofJsonBytes: metricSummary(successes.map((row) => row.proofJsonBytes)),
      peakResidentBytes: metricSummary(successes.map((row) => row.peakResidentBytes)),
      peakPhysicalFootprintBytes: metricSummary(
        successes.map((row) => row.peakPhysicalFootprintBytes),
      ),
      peakTotalPssBytes: metricSummary(successes.map((row) => row.peakTotalPssBytes)),
      peakSampleCount: metricSummary(successes.map((row) => row.peakSampleCount)),
    }];
  }),
);
const summary = {
  schemaVersion: "civicos-mobile-experiment-inventory-v1",
  summarizedAt: new Date().toISOString(),
  sessionCount: sessions.length,
  recordCount: recordRows.length,
  stageObservationCount: stageRows.length,
  payloadObservationCount: payloadRows.length,
  recordsByWorkflow: countBy(recordRows, (row) => row.workflow),
  recordsByExperiment: countBy(recordRows, (row) => row.experimentId || "unspecified"),
  recordsByOutcome: countBy(recordRows, (row) => row.outcome || "unspecified"),
  e1e2: {
    proofRecords: proofRows.length,
    successfulProofRecords: proofRows.filter((row) => row.outcome === "success").length,
    failedProofRecords: proofRows.filter((row) => row.outcome !== "success").length,
    groth16ShapePasses: proofRows.filter((row) => row.hasGroth16Shape).length,
    cohorts: proofCohorts,
  },
  e3: {
    onboardingRecords: onboardingRows.length,
    onboardingSuccesses: onboardingRows.filter((row) => row.outcome === "success").length,
    voteRecords: voteRows.length,
    acceptedVotes: voteRows.filter((row) => row.accepted).length,
    inclusionChecks: inclusionRows.length,
    verifiedInclusions: inclusionRows.filter((row) => row.inclusionFound).length,
  },
  e4: {
    payloadObservations: payloadRows.length,
  },
  e6: {
    cleanupRecords: cleanupRows.length,
    cleanupRecordsWithFailures: cleanupRows.filter((row) =>
      (row.fileDeleteFailures || 0) > 0 || (row.storageTaskFailures || 0) > 0).length,
    exportPrivacyValidationRecords: exportPrivacyRows.length,
    successfulExportPrivacyValidations: exportPrivacyRows
      .filter((row) => row.outcome === "success").length,
  },
  sessions,
};

mkdirSync(outputDir, { recursive: true });
writeFileSync(
  resolve(outputDir, "mobile-session-inventory.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
  { mode: 0o600 },
);
writeFileSync(
  resolve(outputDir, "mobile-session-record-index.jsonl"),
  `${recordRows.map((row) => JSON.stringify(row)).join("\n")}\n`,
  { mode: 0o600 },
);
writeFileSync(
  resolve(outputDir, "mobile-stage-observations.jsonl"),
  `${stageRows.map((row) => JSON.stringify(row)).join("\n")}\n`,
  { mode: 0o600 },
);
writeFileSync(
  resolve(outputDir, "mobile-application-payloads.jsonl"),
  `${payloadRows.map((row) => JSON.stringify(row)).join("\n")}\n`,
  { mode: 0o600 },
);
writeFileSync(
  resolve(outputDir, "mobile-proof-runs.jsonl"),
  `${proofRows.map((row) => JSON.stringify(row)).join("\n")}\n`,
  { mode: 0o600 },
);
const memoryColumns = [
  "sessionId", "recordId", "cohort", "sequence", "beforeResidentBytes",
  "beforePhysicalFootprintBytes", "beforeProofResidentBytes",
  "beforeProofPhysicalFootprintBytes", "peakResidentBytes",
  "peakPhysicalFootprintBytes", "peakTotalPssBytes", "peakSampleCount",
  "afterProofResidentBytes", "afterProofPhysicalFootprintBytes",
  "afterSettleResidentBytes", "afterSettlePhysicalFootprintBytes", "settleDelayMs",
];
writeFileSync(
  resolve(outputDir, "mobile-memory-samples.csv"),
  `${[
    memoryColumns.join(","),
    ...memoryRows.map((row) => memoryColumns.map((column) => csvValue(row[column])).join(",")),
  ].join("\n")}\n`,
  { mode: 0o600 },
);
console.log(JSON.stringify({
  sessionCount: summary.sessionCount,
  recordCount: summary.recordCount,
  stageObservationCount: summary.stageObservationCount,
  payloadObservationCount: summary.payloadObservationCount,
  proofRunCount: proofRows.length,
}, null, 2));
