#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);
const backendRoot = resolve(scriptDir, "../..");
const manifestFilename = "evidence-collection-manifest.json";
const supportedSchema = "civicos-evidence-collection-config-v1";

const sha256Bytes = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sha256File = (path) => sha256Bytes(readFileSync(path));
const utcFilename = () => new Date().toISOString().replace(/[:.]/gu, "-");
const safeLabel = (value, fallback) => {
  const normalized = String(value || "")
    .trim()
    .replace(/[^a-z0-9_-]+/giu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, 80);
  return normalized || fallback;
};
const asObject = (value) => value && typeof value === "object" && !Array.isArray(value)
  ? value
  : {};
const unique = (values) => [...new Set(values)];

const valueFor = (args, name) => {
  const directIndex = args.indexOf(name);
  if (directIndex >= 0) return args[directIndex + 1] || null;
  const prefix = `${name}=`;
  const inline = args.find((entry) => entry.startsWith(prefix));
  return inline ? inline.slice(prefix.length) : null;
};

const valuesFor = (args, name) => {
  const values = [];
  const prefix = `${name}=`;
  for (const [index, entry] of args.entries()) {
    if (entry === name && args[index + 1]) values.push(args[index + 1]);
    if (entry.startsWith(prefix)) values.push(entry.slice(prefix.length));
  }
  return values;
};

const parseTarget = (value, baseDir) => {
  const [label, ...pathParts] = String(value || "").split("=");
  if (!label || pathParts.length === 0 || !pathParts.join("=").trim()) {
    throw new Error(`Invalid privacy target: ${value}`);
  }
  return {
    label: safeLabel(label, "target"),
    path: resolve(baseDir, pathParts.join("=")),
  };
};

const resolveConfiguredPath = (baseDir, value) => value ? resolve(baseDir, String(value)) : null;

export const normalizeEvidenceConfig = ({ rawConfig = {}, configDir = process.cwd(), args = [] } = {}) => {
  if (rawConfig.schemaVersion && rawConfig.schemaVersion !== supportedSchema) {
    throw new Error(`Unsupported evidence collection config schema: ${rawConfig.schemaVersion}`);
  }
  const historical = asObject(rawConfig.historicalPollCohort);
  const postgres = asObject(rawConfig.postgresStorage);
  const faults = asObject(rawConfig.faultTrials);
  const privacy = asObject(rawConfig.privacyAudit);
  const e7e8 = asObject(rawConfig.e7e8);
  const cliSessions = valuesFor(args, "--session").map((path) => resolve(process.cwd(), path));
  const configuredSessions = Array.isArray(rawConfig.mobileSessions)
    ? rawConfig.mobileSessions.map((path) => resolveConfiguredPath(configDir, path)).filter(Boolean)
    : [];
  const configuredTargets = Array.isArray(privacy.targets)
    ? privacy.targets.map((target) => {
      if (typeof target === "string") return parseTarget(target, configDir);
      const targetObject = asObject(target);
      if (!targetObject.label || !targetObject.path) {
        throw new Error("Every privacy target requires label and path.");
      }
      return {
        label: safeLabel(targetObject.label, "target"),
        path: resolveConfiguredPath(configDir, targetObject.path),
      };
    })
    : [];
  const cliTargets = valuesFor(args, "--privacy-target")
    .map((target) => parseTarget(target, process.cwd()));
  const cliMarkerFile = valueFor(args, "--privacy-markers");
  const cliCeremonyFile = valueFor(args, "--ceremony");
  const cliReviewFile = valueFor(args, "--review");

  return {
    mobileSessions: unique([...configuredSessions, ...cliSessions]),
    historicalPollCohort: {
      enabled: historical.enabled === true
        || args.includes("--run-poll-cohort"),
      backendUrl: valueFor(args, "--poll-cohort-backend-url")
        || String(historical.backendUrl || "").trim()
        || null,
      expectedPollCount: Number(
        valueFor(args, "--expected-poll-count") || historical.expectedPollCount || 4,
      ),
    },
    postgresStorage: {
      enabled: postgres.enabled === true || args.includes("--run-postgres-storage"),
      label: safeLabel(valueFor(args, "--postgres-label") || postgres.label, "current-dataset"),
    },
    faultTrials: {
      enabled: faults.enabled === true || args.includes("--run-faults"),
    },
    privacyAudit: {
      enabled: privacy.enabled === true || Boolean(cliMarkerFile) || cliTargets.length > 0,
      markerFile: cliMarkerFile
        ? resolve(process.cwd(), cliMarkerFile)
        : resolveConfiguredPath(configDir, privacy.markerFile),
      targets: [...configuredTargets, ...cliTargets],
    },
    e7e8: {
      enabled: e7e8.enabled === true || Boolean(cliCeremonyFile) || Boolean(cliReviewFile),
      ceremonyFile: cliCeremonyFile
        ? resolve(process.cwd(), cliCeremonyFile)
        : resolveConfiguredPath(configDir, e7e8.ceremonyFile),
      reviewFile: cliReviewFile
        ? resolve(process.cwd(), cliReviewFile)
        : resolveConfiguredPath(configDir, e7e8.reviewFile),
    },
    outputRoot: valueFor(args, "--output-dir")
      ? resolve(process.cwd(), valueFor(args, "--output-dir"))
      : resolveConfiguredPath(configDir, rawConfig.outputRoot)
        || resolve(backendRoot, "tmp/experiments/evidence-collections"),
    runLabel: safeLabel(valueFor(args, "--run-label") || rawConfig.runLabel, "evidence"),
  };
};

export const deriveCollectionStatus = (stages, finished = false) => {
  const requested = stages.filter((stage) => stage.status !== "not_requested");
  if (!finished || requested.some((stage) => stage.status === "in_progress")) return "in_progress";
  if (requested.length === 0) return "no_stages_requested";
  if (requested.some((stage) => stage.status === "failed")) return "collector_failed";
  if (requested.some((stage) => stage.status === "blocked")) return "collector_incomplete";
  return "collectors_completed";
};

const readDotEnvNames = (path) => {
  if (!existsSync(path)) return new Set();
  return new Set(readFileSync(path, "utf8").split(/\r?\n/gu).flatMap((line) => {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=/u.exec(line.trim());
    return match ? [match[1]] : [];
  }));
};

const missingFiles = (paths) => paths.filter((path) => !path || !existsSync(path));

const listFiles = (path) => {
  if (!existsSync(path)) return [];
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) return [];
  if (stat.isFile()) return [path];
  if (!stat.isDirectory()) return [];
  return readdirSync(path).flatMap((entry) => listFiles(resolve(path, entry)));
};

const artifactRows = (runRoot, stageDir) => listFiles(stageDir)
  .sort()
  .map((path) => ({
    path: relative(runRoot, path),
    bytes: lstatSync(path).size,
    sha256: sha256File(path),
  }));

const writePrivate = (path, value) => {
  writeFileSync(path, value, { mode: 0o600 });
};

const commandExists = (command) => spawnSync(command, ["--version"], {
  cwd: backendRoot,
  encoding: "utf8",
  stdio: "ignore",
}).status === 0;

const gitRevision = () => {
  const result = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: backendRoot,
    encoding: "utf8",
  });
  return result.status === 0 ? result.stdout.trim() : null;
};

const inputFileRow = (path) => ({
  filename: basename(path),
  bytes: lstatSync(path).size,
  sha256: sha256File(path),
});

const baseStages = (config) => [
  {
    stageId: "mobile-session-inventory",
    experiments: ["E1", "E2", "E3", "E4", "E6"],
    status: config.mobileSessions.length > 0 ? "pending" : "not_requested",
    completionMeaning: "Supplied mobile sessions were indexed into records, stage observations, payload observations, and aggregate counts.",
  },
  {
    stageId: "mobile-proof-verification",
    experiments: ["E1", "E2"],
    status: config.mobileSessions.length > 0 ? "pending" : "not_requested",
    completionMeaning: "Every supplied synthetic benchmark proof was checked with the pinned verification key.",
  },
  {
    stageId: "historical-poll-cohort",
    experiments: ["E3"],
    status: config.historicalPollCohort.enabled ? "pending" : "not_requested",
    completionMeaning: "The read-only registered poll-cohort checks completed; inspect qualificationGatePassed and per-poll outcomes separately.",
  },
  {
    stageId: "postgres-storage",
    experiments: ["E4"],
    status: config.postgresStorage.enabled ? "pending" : "not_requested",
    completionMeaning: "The PostgreSQL size query completed for the operator-prepared dataset.",
  },
  {
    stageId: "fault-trials",
    experiments: ["E5"],
    status: config.faultTrials.enabled ? "pending" : "not_requested",
    completionMeaning: "The implemented isolated-service fault strata and database invariant checks completed.",
  },
  {
    stageId: "privacy-marker-audit",
    experiments: ["E6"],
    status: config.privacyAudit.enabled ? "pending" : "not_requested",
    completionMeaning: "Exact markers were scanned in every supplied extract.",
  },
  {
    stageId: "e7-e8-validation",
    experiments: ["E7", "E8"],
    status: config.e7e8.enabled ? "pending" : "not_requested",
    completionMeaning: "The supplied ceremony and review manifests and referenced files passed structural and hash validation.",
  },
];

const claimBoundaries = {
  E1: "Apply the registered device, trial-count, exclusion, and proof-verification gates.",
  E2: "Analyze native memory fields and retain any registered profiler requirement.",
  E3: "Historical checks do not replace prospective onboarding, vote, receipt, and inclusion cohorts.",
  E4: "Repeat application, wire, artifact, and dedicated-database size measurements at every registered size.",
  E5: "The automated fault runner covers only its registered strata; external failure injection remains separate.",
  E6: "Exact-marker scanning does not replace encoded-data inspection, retention checks, or reviewer sampling.",
  E7: "Validation checks supplied evidence; independent contributions and the ceremony must occur first.",
  E8: "Validation checks supplied evidence; an independent reviewer must perform the review first.",
};

const runCommand = ({
  label,
  command,
  args,
  env,
  runRoot,
  stageDir,
  stdoutFilename = "collector.stdout.log",
}) => {
  console.log(`[CivicOSEvidence] ${label} in_progress`);
  const startedAtUtc = new Date().toISOString();
  mkdirSync(stageDir, { recursive: true });
  const result = spawnSync(command, args, {
    cwd: backendRoot,
    encoding: "utf8",
    env,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.stdout) writePrivate(resolve(stageDir, stdoutFilename), result.stdout);
  if (result.stderr) writePrivate(resolve(stageDir, "collector.stderr.log"), result.stderr);
  const status = result.status === 0 ? "completed" : "failed";
  console.log(`[CivicOSEvidence] ${label} ${status}`);
  return {
    status,
    startedAtUtc,
    finishedAtUtc: new Date().toISOString(),
    exitCode: result.status,
    signal: result.signal || null,
    errorClass: result.error?.name || null,
    artifacts: artifactRows(runRoot, stageDir),
  };
};

const main = () => {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log("Usage: node run-evidence-collection.mjs [--config private-config.json] [--output-dir private-dir] [--session mobile.json] [--run-poll-cohort] [--run-postgres-storage] [--run-faults] [--privacy-markers markers.json --privacy-target=label=path] [--ceremony ceremony.json --review review.json]");
    return;
  }
  const configPathArg = valueFor(args, "--config");
  const configPath = configPathArg ? resolve(process.cwd(), configPathArg) : null;
  const rawConfig = configPath ? JSON.parse(readFileSync(configPath, "utf8")) : {};
  const config = normalizeEvidenceConfig({
    rawConfig,
    configDir: configPath ? dirname(configPath) : process.cwd(),
    args,
  });
  const runRoot = resolve(
    config.outputRoot,
    `collection-${utcFilename()}-${config.runLabel}-${randomBytes(4).toString("hex")}`,
  );
  mkdirSync(runRoot, { recursive: true });

  const stages = baseStages(config);
  const manifest = {
    schemaVersion: "civicos-evidence-collection-manifest-v1",
    collectionStatus: "in_progress",
    claimStatus: "not_evaluated",
    startedAtUtc: new Date().toISOString(),
    finishedAtUtc: null,
    backendRevision: gitRevision(),
    nodeVersion: process.version,
    coordinatorSha256: sha256File(scriptPath),
    configuration: {
      configFile: configPath ? inputFileRow(configPath) : null,
      mobileSessionCount: config.mobileSessions.length,
      historicalPollCohort: config.historicalPollCohort.enabled,
      expectedPollCount: config.historicalPollCohort.enabled
        ? config.historicalPollCohort.expectedPollCount
        : null,
      postgresStorage: config.postgresStorage.enabled,
      postgresLabel: config.postgresStorage.enabled ? config.postgresStorage.label : null,
      faultTrials: config.faultTrials.enabled,
      privacyAudit: config.privacyAudit.enabled,
      privacyTargetLabels: config.privacyAudit.targets.map((target) => target.label),
      e7e8Validation: config.e7e8.enabled,
    },
    sourceInputs: [],
    stages,
    claimBoundaries,
  };
  const manifestPath = resolve(runRoot, manifestFilename);
  const saveManifest = (finished = false) => {
    manifest.collectionStatus = deriveCollectionStatus(stages, finished);
    writePrivate(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  };
  const stageById = (stageId) => stages.find((stage) => stage.stageId === stageId);
  const blockStage = (stage, label, reasons) => {
    stage.status = "blocked";
    stage.startedAtUtc = null;
    stage.finishedAtUtc = new Date().toISOString();
    stage.blockedReasons = reasons;
    console.log(`[CivicOSEvidence] ${label} blocked`);
    saveManifest();
  };
  const executeStage = (stage, options) => {
    stage.status = "in_progress";
    saveManifest();
    Object.assign(stage, runCommand(options));
    saveManifest();
  };

  saveManifest();
  const dotenvNames = readDotEnvNames(resolve(backendRoot, ".env"));
  const hasEnv = (name, allowDotEnv = false) => Boolean(String(process.env[name] || "").trim())
    || (allowDotEnv && dotenvNames.has(name));

  const mobileInventoryStage = stageById("mobile-session-inventory");
  const mobileProofStage = stageById("mobile-proof-verification");
  if (mobileInventoryStage.status === "pending") {
    const missing = missingFiles(config.mobileSessions);
    if (missing.length > 0) {
      blockStage(mobileInventoryStage, "E1-E4-E6", [
        `Missing ${missing.length} supplied mobile session file(s).`,
      ]);
      blockStage(mobileProofStage, "E1-E2", [
        `Missing ${missing.length} supplied mobile session file(s).`,
      ]);
    } else {
      manifest.sourceInputs.push(...config.mobileSessions.map((path) => ({
        role: "mobile-session",
        ...inputFileRow(path),
      })));
      const inventoryDir = resolve(runRoot, "mobile-session-inventory");
      executeStage(mobileInventoryStage, {
        label: "E1-E4-E6",
        command: process.execPath,
        args: [
          resolve(scriptDir, "summarize-mobile-experiment-exports.mjs"),
          ...config.mobileSessions.flatMap((path) => ["--session", path]),
          "--output-dir",
          inventoryDir,
        ],
        env: process.env,
        runRoot,
        stageDir: inventoryDir,
      });
      const benchmarkSessions = config.mobileSessions.filter((path) => {
        const session = JSON.parse(readFileSync(path, "utf8"));
        return session.records?.some((record) => record?.workflow === "mobile_zkp_benchmark");
      });
      if (benchmarkSessions.length === 0) {
        mobileProofStage.status = "not_requested";
        saveManifest();
      } else {
        const stageDir = resolve(runRoot, "e1-e2-mobile-verification");
        executeStage(mobileProofStage, {
          label: "E1-E2",
          command: process.execPath,
          args: [
            resolve(scriptDir, "verify-mobile-benchmark-exports.mjs"),
            ...benchmarkSessions.flatMap((path) => ["--session", path]),
            "--output-dir",
            stageDir,
          ],
          env: process.env,
          runRoot,
          stageDir,
        });
      }
    }
  }

  const historicalStage = stageById("historical-poll-cohort");
  if (historicalStage.status === "pending") {
    const requiredEnv = [
      "SUPABASE_URL",
      "SUPABASE_SERVICE_ROLE_KEY",
    ];
    const missing = requiredEnv.filter((name) => !hasEnv(name, true));
    if (
      !config.historicalPollCohort.backendUrl
      && !hasEnv("CIVICOS_EXPERIMENT_BACKEND_URL", true)
    ) {
      missing.push("CIVICOS_EXPERIMENT_BACKEND_URL");
    }
    if (
      !Number.isInteger(config.historicalPollCohort.expectedPollCount)
      || config.historicalPollCohort.expectedPollCount < 1
      || config.historicalPollCohort.expectedPollCount > 100
    ) {
      missing.push("valid expectedPollCount");
    }
    if (missing.length > 0) {
      blockStage(historicalStage, "E3", [`Missing environment values: ${missing.join(", ")}.`]);
    } else {
      const stageDir = resolve(runRoot, "e3-historical-poll-cohort");
      executeStage(historicalStage, {
        label: "E3",
        command: process.execPath,
        args: [resolve(scriptDir, "collect-poll-cohort-evidence.mjs")],
        env: {
          ...process.env,
          CIVICOS_EXPERIMENT_OUTPUT_DIR: stageDir,
          CIVICOS_EXPERIMENT_EXPECTED_POLL_COUNT: String(
            config.historicalPollCohort.expectedPollCount,
          ),
          ...(config.historicalPollCohort.backendUrl
            ? { CIVICOS_EXPERIMENT_BACKEND_URL: config.historicalPollCohort.backendUrl }
            : null),
        },
        runRoot,
        stageDir,
      });
    }
  }

  const postgresStage = stageById("postgres-storage");
  if (postgresStage.status === "pending") {
    const reasons = [];
    const postgresUrl = String(process.env.CIVICOS_EXPERIMENT_POSTGRES_URL || "").trim();
    const hasLibpqConnection = Boolean(
      postgresUrl
      || process.env.PGSERVICE
      || process.env.PGHOST
      || process.env.PGDATABASE,
    );
    if (process.env.CIVICOS_EXPERIMENT_CONFIRM_DEDICATED_DATABASE !== "true") {
      reasons.push("CIVICOS_EXPERIMENT_CONFIRM_DEDICATED_DATABASE must equal true.");
    }
    if (!hasLibpqConnection) {
      reasons.push("Set CIVICOS_EXPERIMENT_POSTGRES_URL or explicit libpq PG connection variables.");
    }
    if (!commandExists("psql")) reasons.push("psql is unavailable.");
    if (reasons.length > 0) {
      blockStage(postgresStage, "E4", reasons);
    } else {
      const stageDir = resolve(runRoot, `e4-postgres-${config.postgresStorage.label}`);
      executeStage(postgresStage, {
        label: "E4",
        command: "psql",
        args: ["--no-psqlrc", "--file", resolve(scriptDir, "measure-postgres-storage.sql")],
        env: {
          ...process.env,
          ...(postgresUrl ? { PGDATABASE: postgresUrl } : null),
        },
        runRoot,
        stageDir,
        stdoutFilename: `postgres-storage-${config.postgresStorage.label}.txt`,
      });
    }
  }

  const faultStage = stageById("fault-trials");
  if (faultStage.status === "pending") {
    const requiredEnv = [
      "CIVICOS_FAULT_BASE_URL",
      "CIVICOS_FAULT_POLL_ID",
      "CIVICOS_FAULT_BEARER_TOKEN",
      "CIVICOS_FAULT_VALID_PAYLOAD_FILE",
      "CIVICOS_FAULT_UNIQUE_PAYLOADS_FILE",
      "CIVICOS_EXPERIMENT_PSEUDONYM_KEY",
      "SUPABASE_URL",
      "SUPABASE_SERVICE_ROLE_KEY",
    ];
    const reasons = requiredEnv.filter((name) => !hasEnv(name))
      .map((name) => `Missing environment value: ${name}.`);
    if (process.env.CIVICOS_EXPERIMENT_CONFIRM_ISOLATED !== "true") {
      reasons.push("CIVICOS_EXPERIMENT_CONFIRM_ISOLATED must equal true.");
    }
    const payloadFiles = [
      process.env.CIVICOS_FAULT_VALID_PAYLOAD_FILE,
      process.env.CIVICOS_FAULT_UNIQUE_PAYLOADS_FILE,
    ].filter(Boolean).map((path) => resolve(path));
    if (missingFiles(payloadFiles).length > 0) reasons.push("One or more fault payload files are missing.");
    if (reasons.length > 0) {
      blockStage(faultStage, "E5", reasons);
    } else {
      manifest.sourceInputs.push(...payloadFiles.map((path) => ({
        role: "fault-fixture",
        ...inputFileRow(path),
      })));
      const stageDir = resolve(runRoot, "e5-fault-trials");
      executeStage(faultStage, {
        label: "E5",
        command: process.execPath,
        args: [resolve(scriptDir, "run-vote-fault-trials.mjs")],
        env: { ...process.env, CIVICOS_EXPERIMENT_OUTPUT_DIR: stageDir },
        runRoot,
        stageDir,
      });
    }
  }

  const privacyStage = stageById("privacy-marker-audit");
  if (privacyStage.status === "pending") {
    const reasons = [];
    if (!hasEnv("CIVICOS_EXPERIMENT_PSEUDONYM_KEY")) {
      reasons.push("Missing environment value: CIVICOS_EXPERIMENT_PSEUDONYM_KEY.");
    }
    if (!config.privacyAudit.markerFile || !existsSync(config.privacyAudit.markerFile)) {
      reasons.push("The privacy marker file is missing.");
    }
    if (config.privacyAudit.targets.length === 0) reasons.push("No privacy scan targets were supplied.");
    const missingTargets = config.privacyAudit.targets
      .filter((target) => !existsSync(target.path))
      .map((target) => target.label);
    if (missingTargets.length > 0) reasons.push(`Missing privacy targets: ${missingTargets.join(", ")}.`);
    if (reasons.length > 0) {
      blockStage(privacyStage, "E6", reasons);
    } else {
      manifest.sourceInputs.push({
        role: "privacy-marker-dictionary",
        ...inputFileRow(config.privacyAudit.markerFile),
      });
      const stageDir = resolve(runRoot, "e6-privacy-marker-audit");
      executeStage(privacyStage, {
        label: "E6",
        command: process.execPath,
        args: [
          resolve(scriptDir, "audit-privacy-markers.mjs"),
          "--markers",
          config.privacyAudit.markerFile,
          ...config.privacyAudit.targets.map((target) => `--target=${target.label}=${target.path}`),
          "--output",
          resolve(stageDir, "privacy-marker-audit.json"),
        ],
        env: process.env,
        runRoot,
        stageDir,
      });
    }
  }

  const validationStage = stageById("e7-e8-validation");
  if (validationStage.status === "pending") {
    const inputs = [config.e7e8.ceremonyFile, config.e7e8.reviewFile];
    if (missingFiles(inputs).length > 0) {
      blockStage(validationStage, "E7-E8", ["The ceremony or independent-review manifest is missing."]);
    } else {
      manifest.sourceInputs.push(
        { role: "e7-ceremony-manifest", ...inputFileRow(config.e7e8.ceremonyFile) },
        { role: "e8-review-manifest", ...inputFileRow(config.e7e8.reviewFile) },
      );
      const stageDir = resolve(runRoot, "e7-e8-validation");
      executeStage(validationStage, {
        label: "E7-E8",
        command: process.execPath,
        args: [
          resolve(scriptDir, "validate-e7-e8-evidence.mjs"),
          "--ceremony",
          config.e7e8.ceremonyFile,
          "--review",
          config.e7e8.reviewFile,
        ],
        env: process.env,
        runRoot,
        stageDir,
        stdoutFilename: "e7-e8-validation.json",
      });
    }
  }

  manifest.finishedAtUtc = new Date().toISOString();
  saveManifest(true);
  console.log(`[CivicOSEvidence] collection ${manifest.collectionStatus} ${manifestPath}`);
  if (["collector_failed", "collector_incomplete"].includes(manifest.collectionStatus)) {
    process.exitCode = 1;
  }
};

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) main();
