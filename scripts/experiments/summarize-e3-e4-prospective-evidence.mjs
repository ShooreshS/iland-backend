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
const serverSpanPaths = valuesFor("--server-spans").map((path) => resolve(path));
const pollSummaryPath = valueFor("--poll-summary")
  ? resolve(valueFor("--poll-summary"))
  : null;
const outputDir = resolve(valueFor("--output-dir") || "tmp/experiments/e3-e4-prospective");

if (sessionPaths.length === 0 || serverSpanPaths.length === 0) {
  throw new Error(
    "Provide at least one --session <file> and one --server-spans <file>.",
  );
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const rounded = (value) => Math.round(value * 1000) / 1000;
const finite = (value) => Number.isFinite(value) ? value : null;
const integer = (value) => Number.isInteger(value) ? value : null;
const text = (value) => typeof value === "string" && value.length > 0 ? value : null;
const instantMs = (value) => {
  const parsed = Date.parse(String(value || ""));
  return Number.isFinite(parsed) ? parsed : null;
};
const csvValue = (value) => JSON.stringify(value ?? "");
const fileRow = (path, bytes) => ({
  filename: path.split("/").at(-1),
  bytes: bytes.length,
  sha256: sha256(bytes),
});

const readJsonRecords = (path) => {
  const bytes = readFileSync(path);
  const source = bytes.toString("utf8").trim();
  if (!source) return { bytes, records: [] };
  try {
    const parsed = JSON.parse(source);
    return { bytes, records: Array.isArray(parsed) ? parsed : [parsed] };
  } catch {
    return {
      bytes,
      records: source.split(/\r?\n/u).filter(Boolean).map((line, index) => {
        try {
          return JSON.parse(line);
        } catch {
          throw new Error(`Invalid JSONL at ${path}:${index + 1}.`);
        }
      }),
    };
  }
};

const sessions = [];
const votes = [];
const inclusions = [];
for (const path of sessionPaths) {
  const bytes = readFileSync(path);
  const session = JSON.parse(bytes.toString("utf8"));
  if (
    session.schemaVersion !== "civicos-experiment-session-v1"
    || !session.sessionId
    || !Array.isArray(session.records)
  ) {
    throw new Error(`Unexpected mobile experiment schema in ${path}.`);
  }
  const { export: exportEnvelope, ...sessionContent } = session;
  const computedContentSha256 = sha256(JSON.stringify(sessionContent, null, 2));
  if (
    exportEnvelope?.contentSha256
    && exportEnvelope.contentSha256 !== computedContentSha256
  ) {
    throw new Error(`Export content SHA-256 mismatch in ${path}.`);
  }
  sessions.push({
    ...fileRow(path, bytes),
    sessionId: session.sessionId,
    state: text(session.state),
    exportedAt: text(exportEnvelope?.exportedAt),
    exportContentSha256: text(exportEnvelope?.contentSha256),
    exportContentHashMatches: exportEnvelope?.contentSha256
      ? exportEnvelope.contentSha256 === computedContentSha256
      : null,
    appBuild: text(session.app?.build),
    runtime: text(session.app?.runtime),
    deviceRole: text(session.configuration?.deviceRole),
    networkProfile: text(session.configuration?.networkProfile),
    cohortCode: text(session.configuration?.cohortCode),
    recordCount: session.records.length,
  });
  for (const record of session.records) {
    if (record.workflow === "vote_participation") {
      votes.push({ sessionId: session.sessionId, record });
    }
    if (record.workflow === "audit_receipt_inclusion") {
      inclusions.push({ sessionId: session.sessionId, record });
    }
  }
}

const serverSources = [];
const spans = [];
for (const path of serverSpanPaths) {
  const { bytes, records } = readJsonRecords(path);
  serverSources.push({ ...fileRow(path, bytes), recordCount: records.length });
  for (const record of records) {
    if (
      record?.schemaVersion !== "civicos-server-experiment-span-v1"
      || !record.runId
      || !Array.isArray(record.stages)
    ) {
      throw new Error(`Unexpected server experiment span schema in ${path}.`);
    }
    spans.push(record);
  }
}

const duplicateRunIds = spans
  .map((span) => span.runId)
  .filter((runId, index, values) => values.indexOf(runId) !== index);
if (duplicateRunIds.length > 0) {
  throw new Error("Duplicate server span run IDs were supplied.");
}

const stageByName = (stages, name) => stages.find((stage) => stage?.stage === name) || null;
const payloadFor = (record) => {
  const serialization = stageByName(record.stages || [], "request_serialization");
  const application = stageByName(record.stages || [], "application_payload_observation");
  return {
    compactJsonUtf8Bytes: integer(serialization?.compactJsonUtf8Bytes),
    zkpEnvelopeUtf8Bytes: integer(serialization?.zkpEnvelopeUtf8Bytes),
    zkpOutputUtf8Bytes: integer(serialization?.zkpOutputUtf8Bytes),
    publicInputEnvelopeUtf8Bytes: integer(serialization?.publicInputEnvelopeUtf8Bytes),
    encryptedEnvelopeUtf8Bytes: integer(serialization?.encryptedEnvelopeUtf8Bytes),
    receiptCommitmentUtf8Bytes: integer(serialization?.receiptCommitmentUtf8Bytes),
    requestBodyUtf8Bytes: integer(application?.requestBodyUtf8Bytes),
    responseBodyUtf8Bytes: integer(application?.responseBodyUtf8Bytes),
    httpStatus: integer(application?.httpStatus),
  };
};

const joined = votes.map(({ sessionId, record }) => {
  const matchingSpans = spans.filter((span) => span.runId === record.runId);
  const receiptFingerprint = text(record.result?.receiptFingerprint);
  const matchingInclusions = inclusions.filter(
    ({ record: inclusion }) =>
      receiptFingerprint
      && inclusion.metadata?.receiptFingerprint === receiptFingerprint,
  );
  const backend = matchingSpans.length === 1 ? matchingSpans[0] : null;
  const clientRequest = stageByName(
    record.stages || [],
    "request_upload_and_response_download",
  );
  const serverStageDurationMs = backend
    ? rounded(backend.stages.reduce(
      (sum, stage) => sum + (Number.isFinite(stage.durationMs) ? stage.durationMs : 0),
      0,
    ))
    : null;
  const verifiedInclusions = matchingInclusions.filter(
    ({ record: inclusion }) =>
      inclusion.outcome === "success"
      && inclusion.result?.inclusionFound === true
      && inclusion.result?.rootPresent === true,
  );
  return {
    schemaVersion: "civicos-e3-e4-joined-vote-run-v1",
    sessionId,
    mobileRecordId: text(record.recordId),
    runId: text(record.runId),
    cohort: text(record.cohort),
    networkProfile: text(record.metadata?.networkProfile),
    mobileOutcome: text(record.outcome),
    mobileDurationMs: finite(record.durationMs),
    mobileAccepted: record.result?.accepted === true,
    receiptPresent: record.result?.receiptPresent === true,
    receiptFingerprint,
    backendSpanMatches: matchingSpans.length,
    backendOutcome: text(backend?.outcome),
    backendResponseClass: text(backend?.responseClass),
    backendStartedAt: text(backend?.startedAt),
    backendCompletedAt: text(backend?.completedAt),
    backendDurationMs: finite(backend?.durationMs),
    backendStageDurationMs: serverStageDurationMs,
    clientRequestDurationMs: finite(clientRequest?.durationMs),
    clientRequestMinusServerMs:
      Number.isFinite(clientRequest?.durationMs) && Number.isFinite(backend?.durationMs)
        ? rounded(clientRequest.durationMs - backend.durationMs)
        : null,
    inclusionChecks: matchingInclusions.length,
    verifiedInclusionChecks: verifiedInclusions.length,
    latestProofStepCount: integer(verifiedInclusions.at(-1)?.record?.result?.proofStepCount),
    payload: payloadFor(record),
    acceptanceJoinPassed:
      record.outcome === "success"
      && record.result?.accepted === true
      && record.result?.receiptPresent === true
      && matchingSpans.length === 1
      && backend?.outcome === "success"
      && backend?.responseClass === "ACCEPTED",
    receiptInclusionPassed: verifiedInclusions.length > 0,
  };
});

const stageRows = spans.flatMap((span) => span.stages.map((stage, index) => ({
  runId: span.runId,
  sequence: index + 1,
  stage: text(stage.stage),
  durationMs: finite(stage.durationMs),
  outcome: text(stage.outcome),
  errorClass: text(stage.errorClass),
})));

let pollSnapshot = null;
let pollSource = null;
let pollAcceptanceRecords = [];
if (pollSummaryPath) {
  const bytes = readFileSync(pollSummaryPath);
  const poll = JSON.parse(bytes.toString("utf8"));
  if (poll.schemaVersion !== "civicos-historical-poll-cohort-evidence-v1") {
    throw new Error("Unexpected poll evidence summary schema.");
  }
  pollSource = fileRow(pollSummaryPath, bytes);
  pollAcceptanceRecords = (poll.polls || []).flatMap((entry) =>
    (entry.voteRecordHashes || []).map((vote) => ({
      pollCode: text(entry.pollCode),
      acceptedAt: text(vote.acceptedAt),
    }))
  );
  pollSnapshot = {
    collectedAt: text(poll.collectedAt),
    cluster: text(poll.cluster),
    expectedPollCount: integer(poll.expectedPollCount),
    examined: integer(poll.examined),
    cohortCountMatches: poll.cohortCountMatches === true,
    qualified: integer(poll.qualified),
    qualificationGatePassed: poll.qualificationGatePassed === true,
    acceptedVoteCount: integer(poll.acceptedVoteCount),
    rootPublicationCount: integer(poll.rootPublicationCount),
    tallyVerificationCount: integer(poll.tallyVerificationCount),
    finalPublicationCount: integer(poll.finalPublicationCount),
    pollStates: (poll.polls || []).map((entry) => ({
      pollCode: text(entry.pollCode),
      status: text(entry.status),
      publicationMode: text(entry.publicationMode),
      acceptedVoteCount: integer(entry.acceptedVoteCount),
      allVotesVerified: entry.allVotesVerified === true,
      allVoteEvidencePresent: entry.allVoteEvidencePresent === true,
      uniqueNullifierCount: integer(entry.uniqueNullifierCount),
      allNullifiersUniqueWithinPoll: entry.allNullifiersUniqueWithinPoll === true,
      rootPublicationCount: Array.isArray(entry.roots) ? entry.roots.length : 0,
      verifiedTallyCount: Array.isArray(entry.tallies)
        ? entry.tallies.filter((tally) => tally.verifierAccepted === true).length
        : 0,
      publicAuditVerifierPassed: entry.publicAuditVerifierPassed === true,
      finalPublicationCount: integer(entry.finalPublicationCount),
      qualified: entry.qualified === true,
    })),
  };
}

const temporalPublicationLinks = joined.map((row) => {
  const startedAtMs = instantMs(row.backendStartedAt);
  const completedAtMs = instantMs(row.backendCompletedAt);
  const matches = pollAcceptanceRecords.filter((record) => {
    const acceptedAtMs = instantMs(record.acceptedAt);
    return acceptedAtMs !== null
      && startedAtMs !== null
      && completedAtMs !== null
      && acceptedAtMs >= startedAtMs
      && acceptedAtMs <= completedAtMs;
  });
  const acceptedAtMs = matches.length === 1 ? instantMs(matches[0].acceptedAt) : null;
  return {
    runId: row.runId,
    method: "unique_poll_acceptance_timestamp_within_backend_span",
    matchCount: matches.length,
    pollCode: matches.length === 1 ? matches[0].pollCode : null,
    acceptedOffsetFromServerStartMs:
      acceptedAtMs !== null && startedAtMs !== null
        ? rounded(acceptedAtMs - startedAtMs)
        : null,
    passed: matches.length === 1,
  };
});
const contextualPublicationLinkPassed =
  joined.length > 0
  && temporalPublicationLinks.length === joined.length
  && temporalPublicationLinks.every((row) => row.passed)
  && pollSnapshot?.acceptedVoteCount === joined.length;

const limitations = [];
const networkProfiles = [...new Set(joined.map((row) => row.networkProfile).filter(Boolean))];
if (networkProfiles.includes("proof_offline")) {
  limitations.push("The session is labeled proof_offline rather than a registered E3 network profile.");
}
if (joined.length < 30) {
  limitations.push("The prospective vote cohort has fewer than 30 joined observations.");
}
if (joined.length !== spans.length) {
  limitations.push("The supplied mobile vote and server-span counts differ.");
}
if (pollSnapshot && !pollSnapshot.qualificationGatePassed) {
  limitations.push("The poll snapshot did not pass the complete publication gate.");
}
if (pollSnapshot && !contextualPublicationLinkPassed) {
  limitations.push("The supplied backend spans did not each contain one unique poll acceptance timestamp.");
}
if (pollSnapshot?.acceptedVoteCount !== null && pollSnapshot?.acceptedVoteCount !== joined.length) {
  limitations.push("The poll contains accepted votes without matching supplied mobile/server records.");
}

const summary = {
  schemaVersion: "civicos-e3-e4-prospective-summary-v1",
  summarizedAt: new Date().toISOString(),
  dataStatus: "prospective_smoke_collected",
  sources: {
    mobileSessions: sessions,
    serverSpans: serverSources,
    pollSummary: pollSource,
  },
  counts: {
    mobileVoteRecords: votes.length,
    mobileAcceptedVotes: votes.filter(({ record }) => record.result?.accepted === true).length,
    serverSpans: spans.length,
    joinedVoteRuns: joined.length,
    acceptanceJoinsPassed: joined.filter((row) => row.acceptanceJoinPassed).length,
    receiptInclusionJoinsPassed: joined.filter((row) => row.receiptInclusionPassed).length,
    inclusionChecks: inclusions.length,
    successfulInclusionChecks: inclusions.filter(
      ({ record }) => record.outcome === "success" && record.result?.inclusionFound === true,
    ).length,
  },
  joinedRuns: joined,
  pollSnapshot,
  temporalPublicationLinks,
  gates: {
    instrumentedAcceptanceSmokePassed:
      joined.length > 0
      && joined.every((row) => row.acceptanceJoinPassed && row.receiptInclusionPassed),
    registeredProspectiveCohortPassed: joined.length >= 30 && limitations.length === 0,
    completePublicationGatePassed: pollSnapshot?.qualificationGatePassed === true,
    prospectiveEndToEndFunctionalGatePassed:
      contextualPublicationLinkPassed
      && joined.every((row) => row.acceptanceJoinPassed && row.receiptInclusionPassed)
      && pollSnapshot?.qualificationGatePassed === true,
    e4ApplicationPayloadCohortPassed:
      joined.filter((row) => Number.isInteger(row.payload.requestBodyUtf8Bytes)).length >= 30,
  },
  limitations,
};

mkdirSync(outputDir, { recursive: true });
writeFileSync(
  resolve(outputDir, "prospective-e3-e4-summary.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
  { mode: 0o600 },
);
writeFileSync(
  resolve(outputDir, "joined-vote-runs.jsonl"),
  `${joined.map((row) => JSON.stringify(row)).join("\n")}\n`,
  { mode: 0o600 },
);

const stageColumns = ["runId", "sequence", "stage", "durationMs", "outcome", "errorClass"];
writeFileSync(
  resolve(outputDir, "server-stage-observations.csv"),
  `${[
    stageColumns.join(","),
    ...stageRows.map((row) => stageColumns.map((column) => csvValue(row[column])).join(",")),
  ].join("\n")}\n`,
  { mode: 0o600 },
);

const payloadColumns = [
  "runId", "compactJsonUtf8Bytes", "zkpEnvelopeUtf8Bytes", "zkpOutputUtf8Bytes",
  "publicInputEnvelopeUtf8Bytes", "encryptedEnvelopeUtf8Bytes",
  "receiptCommitmentUtf8Bytes", "requestBodyUtf8Bytes", "responseBodyUtf8Bytes",
  "httpStatus",
];
writeFileSync(
  resolve(outputDir, "application-payload-observations.csv"),
  `${[
    payloadColumns.join(","),
    ...joined.map((row) => payloadColumns.map((column) => csvValue(
      column === "runId" ? row.runId : row.payload[column],
    )).join(",")),
  ].join("\n")}\n`,
  { mode: 0o600 },
);

console.log(JSON.stringify({
  mobileVoteRecords: votes.length,
  serverSpans: spans.length,
  acceptanceJoinsPassed: summary.counts.acceptanceJoinsPassed,
  receiptInclusionJoinsPassed: summary.counts.receiptInclusionJoinsPassed,
  instrumentedAcceptanceSmokePassed: summary.gates.instrumentedAcceptanceSmokePassed,
  completePublicationGatePassed: summary.gates.completePublicationGatePassed,
  prospectiveEndToEndFunctionalGatePassed:
    summary.gates.prospectiveEndToEndFunctionalGatePassed,
  outputDir,
}, null, 2));
