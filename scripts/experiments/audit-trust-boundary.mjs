#!/usr/bin/env node

import { createHash, createHmac } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const TRUST_BOUNDARY_SCHEMA_VERSION = "civicos-trust-boundary-audit-v1";

const scriptPath = fileURLToPath(import.meta.url);
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const REPRESENTATIONS = new Set([
  "raw",
  "base64",
  "base64url",
  "hex",
  "json_string",
  "url_component",
  "sha256_hex",
  "sha512_hex",
]);
const EXPECTATIONS = new Set([
  "device_only_raw",
  "derived_server_visible",
  "server_visible",
  "unspecified",
]);
const TARGET_SIDES = new Set(["device", "server", "third_party"]);
const REVIEW_EXPOSURES = new Set([
  "raw",
  "reversible",
  "deterministic_digest",
  "enumerable",
  "inferable",
  "linkable",
  "unobserved",
]);
const EXPOSURE_RANK = Object.freeze({
  unobserved: 0,
  deterministic_digest: 1,
  reversible: 2,
  raw: 3,
});

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const hmacCode = (key, bytes) =>
  createHmac("sha256", key).update(bytes).digest("hex").slice(0, 16);
const safeLabel = (value, field) => {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/gu, "_")
    .replace(/^_+|_+$/gu, "")
    .slice(0, 80);
  if (!normalized) throw new Error(`${field} requires a safe non-empty label.`);
  return normalized;
};
const csvValue = (value) => JSON.stringify(value ?? "");
const writePrivate = (path, value) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, value, { mode: 0o600 });
};

const filesUnder = (path) => {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) {
    throw new Error(`Trust-boundary target contains a symbolic link: ${path}`);
  }
  if (stat.isFile()) {
    if (stat.size > MAX_FILE_BYTES) {
      throw new Error(`Split files larger than 100 MiB before scanning: ${path}`);
    }
    return [path];
  }
  if (!stat.isDirectory()) return [];
  return readdirSync(path).flatMap((entry) => filesUnder(resolve(path, entry)));
};

const readSpecimenBytes = (specimen) => {
  if (typeof specimen.value !== "string" || specimen.value.length === 0) {
    throw new Error(`Specimen ${specimen.specimenId} requires a non-empty value.`);
  }
  if (specimen.inputEncoding === "base64") {
    const bytes = Buffer.from(specimen.value, "base64");
    if (bytes.length < 8) {
      throw new Error(`Specimen ${specimen.specimenId} must contain at least eight bytes.`);
    }
    return bytes;
  }
  if (specimen.inputEncoding && specimen.inputEncoding !== "utf8") {
    throw new Error(`Unsupported inputEncoding for ${specimen.specimenId}.`);
  }
  const bytes = Buffer.from(specimen.value, "utf8");
  if (bytes.length < 8) {
    throw new Error(`Specimen ${specimen.specimenId} must contain at least eight bytes.`);
  }
  return bytes;
};

const representationBytes = (representation, sourceBytes) => {
  if (representation === "raw") return sourceBytes;
  if (representation === "base64") return Buffer.from(sourceBytes.toString("base64"), "utf8");
  if (representation === "base64url") {
    return Buffer.from(sourceBytes.toString("base64url"), "utf8");
  }
  if (representation === "hex") return Buffer.from(sourceBytes.toString("hex"), "utf8");
  if (representation === "sha256_hex") return Buffer.from(sha256(sourceBytes), "utf8");
  if (representation === "sha512_hex") {
    return Buffer.from(createHash("sha512").update(sourceBytes).digest("hex"), "utf8");
  }
  const utf8 = sourceBytes.toString("utf8");
  if (representation === "json_string") return Buffer.from(JSON.stringify(utf8), "utf8");
  if (representation === "url_component") {
    return Buffer.from(encodeURIComponent(utf8), "utf8");
  }
  throw new Error(`Unsupported specimen representation: ${representation}`);
};

const exposureForRepresentation = (representation) => {
  if (representation === "raw") return "raw";
  if (["sha256_hex", "sha512_hex"].includes(representation)) {
    return "deterministic_digest";
  }
  return "reversible";
};

const countOccurrences = (haystack, needle) => {
  if (needle.length === 0 || haystack.length < needle.length) return 0;
  let count = 0;
  let offset = 0;
  while ((offset = haystack.indexOf(needle, offset)) >= 0) {
    count += 1;
    offset += needle.length;
  }
  return count;
};

const isValidSwedishDate = (value) => {
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(4, 6));
  const encodedDay = Number(value.slice(6, 8));
  const day = encodedDay >= 61 && encodedDay <= 91 ? encodedDay - 60 : encodedDay;
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year
    && date.getUTCMonth() === month - 1
    && date.getUTCDate() === day;
};

const hasValidSwedishChecksum = (value) => {
  const tenDigits = value.slice(2);
  const checksum = [...tenDigits.slice(0, 9)].reduce((sum, digit, index) => {
    const product = Number(digit) * (index % 2 === 0 ? 2 : 1);
    return sum + (product > 9 ? product - 9 : product);
  }, 0);
  return (10 - (checksum % 10)) % 10 === Number(tenDigits[9]);
};

export const normalizeIdentifierCandidate = (value, normalizationVersion) => {
  if (typeof value !== "string") return null;
  const compact = value
    .trim()
    .toUpperCase()
    .replace(/[\s<>\-_/.,:;|\\]+/gu, "");
  if (normalizationVersion === 1) return /^\d{10}$/u.test(compact) ? compact : null;
  if (normalizationVersion === 2) {
    return /^\d{12}$/u.test(compact)
      && isValidSwedishDate(compact)
      && hasValidSwedishChecksum(compact)
      ? `SWE:${compact}`
      : null;
  }
  throw new Error(`Unsupported normalization version: ${normalizationVersion}`);
};

const candidateValues = (path) => {
  const text = readFileSync(path, "utf8");
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (Array.isArray(parsed?.candidates)) return parsed.candidates;
  } catch {
    // Newline-delimited candidates are accepted below.
  }
  return text.split(/\r?\n/gu).map((entry) => entry.trim()).filter(Boolean);
};

const runIdentifierTrial = ({ trial, baseDir, pseudonymKey }) => {
  const trialId = safeLabel(trial.trialId, "trialId");
  const observedNidnh = String(trial.observedNidnh || "").trim().toLowerCase();
  if (!/^[0-9a-f]{128}$/u.test(observedNidnh)) {
    throw new Error(`Identifier trial ${trialId} requires a SHA-512 nidnh digest.`);
  }
  if (![1, 2].includes(trial.normalizationVersion)) {
    throw new Error(`Identifier trial ${trialId} has an unsupported normalizationVersion.`);
  }
  const path = resolve(baseDir, String(trial.candidatesFile || ""));
  if (!existsSync(path)) throw new Error(`Candidate file is missing for ${trialId}.`);
  const candidates = candidateValues(path);
  const started = process.hrtime.bigint();
  let checked = 0;
  let invalid = 0;
  let recovered = null;
  for (const candidate of candidates) {
    const normalized = normalizeIdentifierCandidate(candidate, trial.normalizationVersion);
    if (!normalized) {
      invalid += 1;
      continue;
    }
    checked += 1;
    const digest = createHash("sha512").update(normalized).digest("hex");
    if (digest === observedNidnh) {
      recovered = normalized;
      break;
    }
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1_000_000;
  return {
    schemaVersion: "civicos-identifier-reconstruction-trial-v1",
    trialId,
    flowId: safeLabel(trial.flowId || "automatic_identity_success", "flowId"),
    normalizationVersion: trial.normalizationVersion,
    observedDigestCode: hmacCode(pseudonymKey, observedNidnh),
    candidateSetSha256: sha256(readFileSync(path)),
    configuredCandidateSpaceSize: Number.isInteger(trial.candidateSpaceSize)
      ? trial.candidateSpaceSize
      : candidates.length,
    completeCandidateSpace: trial.completeCandidateSpace === true,
    candidatesRead: candidates.length,
    validCandidatesChecked: checked,
    invalidCandidates: invalid,
    recovered: recovered !== null,
    recoveredIdentifierCode: recovered ? hmacCode(pseudonymKey, recovered) : null,
    elapsedMs: Math.round(elapsedMs * 1000) / 1000,
    candidatesPerSecond: elapsedMs > 0
      ? Math.round((checked / (elapsedMs / 1000)) * 1000) / 1000
      : null,
  };
};

const normalizeProtocol = (raw, protocolPath) => {
  if (raw.schemaVersion !== TRUST_BOUNDARY_SCHEMA_VERSION) {
    throw new Error(`Unsupported trust-boundary schema: ${raw.schemaVersion}`);
  }
  const baseDir = dirname(protocolPath);
  if (!Array.isArray(raw.specimens) || raw.specimens.length === 0) {
    throw new Error("The trust-boundary protocol requires at least one specimen.");
  }
  if (!Array.isArray(raw.targets) || raw.targets.length === 0) {
    throw new Error("The trust-boundary protocol requires at least one target.");
  }
  const specimens = raw.specimens.map((entry) => {
    const specimenId = safeLabel(entry.specimenId, "specimenId");
    const dataClass = safeLabel(entry.dataClass, "dataClass");
    const expectation = entry.expectation || "unspecified";
    if (!EXPECTATIONS.has(expectation)) {
      throw new Error(`Unsupported expectation for ${specimenId}: ${expectation}`);
    }
    const representations = Array.isArray(entry.representations)
      ? [...new Set(entry.representations)]
      : ["raw", "base64", "base64url", "hex", "json_string", "url_component"];
    if (representations.length === 0
      || representations.some((value) => !REPRESENTATIONS.has(value))) {
      throw new Error(`Unsupported representation for ${specimenId}.`);
    }
    return {
      specimenId,
      dataClass,
      expectation,
      representations,
      sourceBytes: readSpecimenBytes({ ...entry, specimenId }),
    };
  });
  const targets = raw.targets.map((entry) => {
    const targetId = safeLabel(entry.targetId, "targetId");
    const side = entry.side || "server";
    if (!TARGET_SIDES.has(side)) throw new Error(`Unsupported target side for ${targetId}.`);
    const path = resolve(baseDir, String(entry.path || ""));
    if (!existsSync(path)) throw new Error(`Trust-boundary target is missing: ${targetId}.`);
    return {
      targetId,
      flowId: safeLabel(entry.flowId, "flowId"),
      layer: safeLabel(entry.layer, "layer"),
      checkpoint: safeLabel(entry.checkpoint || "immediate", "checkpoint"),
      side,
      path,
    };
  });
  const targetById = new Map(targets.map((target) => [target.targetId, target]));
  const reviewFindings = (Array.isArray(raw.reviewFindings) ? raw.reviewFindings : [])
    .map((entry) => {
      const findingId = safeLabel(entry.findingId, "findingId");
      const targetId = safeLabel(entry.targetId, "targetId");
      const target = targetById.get(targetId);
      if (!target) throw new Error(`Review finding ${findingId} has an unknown targetId.`);
      const exposureClass = String(entry.exposureClass || "").trim();
      if (!REVIEW_EXPOSURES.has(exposureClass)) {
        throw new Error(`Review finding ${findingId} has an unsupported exposureClass.`);
      }
      const evidencePath = resolve(baseDir, String(entry.evidenceFile || ""));
      if (!entry.evidenceFile || !existsSync(evidencePath)) {
        throw new Error(`Review evidence is missing for ${findingId}.`);
      }
      const evidenceStat = lstatSync(evidencePath);
      if (evidenceStat.isSymbolicLink() || !evidenceStat.isFile()) {
        throw new Error(`Review evidence must be one regular file for ${findingId}.`);
      }
      if (evidenceStat.size > MAX_FILE_BYTES) {
        throw new Error(`Split review evidence larger than 100 MiB for ${findingId}.`);
      }
      const reviewerCodes = Array.isArray(entry.reviewerCodes)
        ? [...new Set(entry.reviewerCodes.map((code) => safeLabel(code, "reviewerCode")))]
        : [];
      if (reviewerCodes.length === 0) {
        throw new Error(`Review finding ${findingId} requires a reviewerCode.`);
      }
      return {
        findingId,
        target,
        dataClass: safeLabel(entry.dataClass, "dataClass"),
        exposureClass,
        method: safeLabel(entry.method, "method"),
        evidencePath,
        reviewerCodes,
        secondReviewerConfirmed: entry.secondReviewerConfirmed === true,
      };
    });
  return {
    cohortId: safeLabel(raw.cohortId || "unassigned", "cohortId"),
    build: String(raw.build || "unassigned").trim().slice(0, 80),
    commit: String(raw.commit || "unassigned").trim().slice(0, 80),
    baseDir,
    specimens,
    targets,
    identifierTrials: Array.isArray(raw.identifierTrials) ? raw.identifierTrials : [],
    reviewFindings,
  };
};

export const runTrustBoundaryAudit = ({
  protocolPath,
  outputDir,
  pseudonymKey,
}) => {
  const resolvedProtocolPath = resolve(protocolPath);
  const resolvedOutputDir = resolve(outputDir);
  if (!pseudonymKey || String(pseudonymKey).trim().length < 16) {
    throw new Error("CIVICOS_EXPERIMENT_PSEUDONYM_KEY must contain at least 16 characters.");
  }
  const protocolBytes = readFileSync(resolvedProtocolPath);
  const protocol = normalizeProtocol(
    JSON.parse(protocolBytes.toString("utf8")),
    resolvedProtocolPath,
  );
  const rows = [];
  const targetInventory = [];

  for (const target of protocol.targets) {
    const files = filesUnder(target.path).sort();
    const fileEntries = files.map((path) => ({
      path,
      relativePath: relative(target.path, path) || ".",
      bytes: readFileSync(path),
    }));
    targetInventory.push({
      targetId: target.targetId,
      flowId: target.flowId,
      layer: target.layer,
      checkpoint: target.checkpoint,
      side: target.side,
      scannedFiles: files.length,
      scannedBytes: fileEntries.reduce((sum, entry) => sum + entry.bytes.length, 0),
      fileHashes: fileEntries.map((entry) => ({
        relativePathCode: hmacCode(pseudonymKey, entry.relativePath),
        sha256: sha256(entry.bytes),
        bytes: entry.bytes.length,
      })),
    });

    for (const specimen of protocol.specimens) {
      const observations = specimen.representations.map((representation) => {
        const needle = representationBytes(representation, specimen.sourceBytes);
        const matches = fileEntries.flatMap((entry) => {
          const count = countOccurrences(entry.bytes, needle);
          return count > 0 ? [{ count, fileSha256: sha256(entry.bytes) }] : [];
        });
        return {
          representation,
          exposureClass: exposureForRepresentation(representation),
          representationCode: hmacCode(pseudonymKey, needle),
          count: matches.reduce((sum, match) => sum + match.count, 0),
          fileHashes: [...new Set(matches.map((match) => match.fileSha256))],
        };
      });
      const positive = observations.filter((entry) => entry.count > 0);
      const highestExposure = positive.reduce(
        (highest, entry) => EXPOSURE_RANK[entry.exposureClass] > EXPOSURE_RANK[highest]
          ? entry.exposureClass
          : highest,
        "unobserved",
      );
      const rawOrReversibleObserved = positive.some((entry) =>
        ["raw", "reversible"].includes(entry.exposureClass));
      const expectationMet = specimen.expectation === "device_only_raw" && target.side !== "device"
        ? !rawOrReversibleObserved
        : null;
      rows.push({
        schemaVersion: "civicos-operator-observation-v1",
        cohortId: protocol.cohortId,
        build: protocol.build,
        commit: protocol.commit,
        flowId: target.flowId,
        targetId: target.targetId,
        targetSide: target.side,
        layer: target.layer,
        checkpoint: target.checkpoint,
        specimenId: specimen.specimenId,
        specimenCode: hmacCode(pseudonymKey, specimen.sourceBytes),
        dataClass: specimen.dataClass,
        expectation: specimen.expectation,
        highestExposure,
        rawOrReversibleObserved,
        expectationMet,
        totalMatches: positive.reduce((sum, entry) => sum + entry.count, 0),
        representations: observations,
      });
    }
  }

  const reconstructionTrials = protocol.identifierTrials.map((trial) =>
    runIdentifierTrial({ trial, baseDir: protocol.baseDir, pseudonymKey }));
  const reviewFindings = protocol.reviewFindings.map((finding) => {
    const evidenceBytes = readFileSync(finding.evidencePath);
    return {
      schemaVersion: "civicos-operator-review-finding-v1",
      findingId: finding.findingId,
      targetId: finding.target.targetId,
      targetSide: finding.target.side,
      flowId: finding.target.flowId,
      layer: finding.target.layer,
      checkpoint: finding.target.checkpoint,
      dataClass: finding.dataClass,
      exposureClass: finding.exposureClass,
      method: finding.method,
      evidenceSha256: sha256(evidenceBytes),
      evidenceBytes: evidenceBytes.length,
      reviewerCodes: finding.reviewerCodes,
      secondReviewerConfirmed: finding.secondReviewerConfirmed,
    };
  });
  const exactScanFailures = rows.filter((entry) =>
    entry.targetSide !== "device" && entry.rawOrReversibleObserved);
  const reviewedRawLocalityFailures = reviewFindings.filter((entry) =>
    entry.targetSide !== "device" && ["raw", "reversible"].includes(entry.exposureClass));
  const report = {
    schemaVersion: TRUST_BOUNDARY_SCHEMA_VERSION,
    auditedAt: new Date().toISOString(),
    cohortId: protocol.cohortId,
    build: protocol.build,
    commit: protocol.commit,
    protocolSha256: sha256(protocolBytes),
    scannerSha256: sha256(readFileSync(scriptPath)),
    scope: {
      targetCount: protocol.targets.length,
      specimenCount: protocol.specimens.length,
      identifierTrialCount: reconstructionTrials.length,
      reviewFindingCount: reviewFindings.length,
    },
    claimStatus: "not_evaluated",
    automatedRawLocalityGate: {
      status: exactScanFailures.length > 0 || reviewedRawLocalityFailures.length > 0
        ? "failed"
        : "requires_registered_review",
      exactScanFailureCount: exactScanFailures.length,
      reviewedFailureCount: reviewedRawLocalityFailures.length,
    },
    targetInventory,
    observations: rows,
    identifierReconstruction: reconstructionTrials,
    reviewFindings,
  };

  const columns = [
    "cohortId", "build", "commit", "flowId", "targetId", "targetSide", "layer",
    "checkpoint", "specimenId", "specimenCode", "dataClass", "expectation",
    "highestExposure", "rawOrReversibleObserved", "expectationMet", "totalMatches",
  ];
  writePrivate(
    resolve(resolvedOutputDir, "operator-observation-matrix.csv"),
    `${[
      columns.join(","),
      ...rows.map((row) => columns.map((column) => csvValue(row[column])).join(",")),
    ].join("\n")}\n`,
  );
  writePrivate(
    resolve(resolvedOutputDir, "reconstruction-trials.jsonl"),
    reconstructionTrials.length > 0
      ? `${reconstructionTrials.map((entry) => JSON.stringify(entry)).join("\n")}\n`
      : "",
  );
  writePrivate(
    resolve(resolvedOutputDir, "operator-review-findings.jsonl"),
    reviewFindings.length > 0
      ? `${reviewFindings.map((entry) => JSON.stringify(entry)).join("\n")}\n`
      : "",
  );
  writePrivate(
    resolve(resolvedOutputDir, "trust-boundary-audit.json"),
    `${JSON.stringify(report, null, 2)}\n`,
  );
  return report;
};

const valueFor = (args, name) => {
  const index = args.indexOf(name);
  if (index >= 0) return args[index + 1] || null;
  const inline = args.find((entry) => entry.startsWith(`${name}=`));
  return inline ? inline.slice(name.length + 1) : null;
};

const main = () => {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log("Usage: node audit-trust-boundary.mjs --protocol private-protocol.json [--output-dir directory]");
    return;
  }
  const protocolPath = valueFor(args, "--protocol");
  if (!protocolPath) throw new Error("--protocol is required.");
  const outputDir = valueFor(args, "--output-dir")
    || "tmp/experiments/trust-boundary";
  const report = runTrustBoundaryAudit({
    protocolPath,
    outputDir,
    pseudonymKey: String(process.env.CIVICOS_EXPERIMENT_PSEUDONYM_KEY || "").trim(),
  });
  console.log(JSON.stringify({
    outputDir: resolve(outputDir),
    observationCount: report.observations.length,
    rawOrReversibleServerObservations: report.observations.filter((entry) =>
      entry.targetSide !== "device" && entry.rawOrReversibleObserved).length,
    identifierRecoveries: report.identifierReconstruction.filter((entry) => entry.recovered).length,
    reviewedRawLocalityFailures: report.automatedRawLocalityGate.reviewedFailureCount,
    automatedRawLocalityGate: report.automatedRawLocalityGate.status,
    claimStatus: report.claimStatus,
  }, null, 2));
};

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) main();
