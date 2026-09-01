import { appendFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const RUN_ID_PATTERN = /^[a-z0-9_-]{8,96}$/i;
const ENABLED_VALUES = new Set(["1", "true", "yes"]);
const allowedStages = new Set([
  "authentication",
  "request_parse_and_validation",
  "poll_and_policy_fetch",
  "eligibility_evaluation",
  "encryption_material_lookup",
  "proof_verification",
  "duplicate_check",
  "database_commit_and_audit",
  "receipt_construction",
]);

type ExperimentStage = {
  stage: string;
  durationMs: number;
  outcome: "success" | "failure";
  errorClass?: string;
};

export type VoteExperimentSpanCollector = {
  runId: string;
  measure<T>(stage: string, operation: () => Promise<T> | T): Promise<T>;
  addResult(result: { success: boolean; responseClass: string }): void;
  finish(): Promise<void>;
};

let writeQueue = Promise.resolve();

const enabled = () =>
  ENABLED_VALUES.has(
    String(process.env.CIVICOS_ENABLE_EXPERIMENT_COLLECTOR || "")
      .trim()
      .toLowerCase(),
  );

const errorClass = (error: unknown) => {
  if (error && typeof error === "object") {
    const candidate = "code" in error ? error.code : "name" in error ? error.name : null;
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.replace(/[^a-z0-9_-]/gi, "_").slice(0, 80).toUpperCase();
    }
  }
  return "UNCLASSIFIED_ERROR";
};

const roundMs = (value: number) => Math.max(0, Math.round(value * 1000) / 1000);

const writeRecord = (record: Record<string, unknown>) => {
  const configuredPath = String(process.env.CIVICOS_EXPERIMENT_LOG_PATH || "").trim();
  const line = `${JSON.stringify(record)}\n`;
  if (!configuredPath) {
    console.info("[experiment]", line.trim());
    return Promise.resolve();
  }

  const outputPath = resolve(configuredPath);
  const operation = writeQueue.then(async () => {
    await mkdir(dirname(outputPath), { recursive: true });
    await appendFile(outputPath, line, { encoding: "utf8", mode: 0o600 });
  });
  writeQueue = operation.catch(() => undefined);
  return operation;
};

export const createVoteExperimentSpanCollector = (
  rawRunId: string | null,
): VoteExperimentSpanCollector | null => {
  const runId = String(rawRunId || "").trim();
  if (!enabled() || !RUN_ID_PATTERN.test(runId)) {
    return null;
  }

  const startedAt = new Date().toISOString();
  const startedAtMonotonic = performance.now();
  const stages: ExperimentStage[] = [];
  let result: { success: boolean; responseClass: string } | null = null;
  let finished = false;

  return {
    runId,
    async measure<T>(stage: string, operation: () => Promise<T> | T): Promise<T> {
      if (!allowedStages.has(stage)) {
        throw new Error(`Unsupported experiment stage: ${stage}`);
      }
      const stageStartedAt = performance.now();
      try {
        const value = await operation();
        stages.push({
          stage,
          durationMs: roundMs(performance.now() - stageStartedAt),
          outcome: "success",
        });
        return value;
      } catch (error) {
        stages.push({
          stage,
          durationMs: roundMs(performance.now() - stageStartedAt),
          outcome: "failure",
          errorClass: errorClass(error),
        });
        throw error;
      }
    },
    addResult(nextResult) {
      result = {
        success: nextResult.success === true,
        responseClass: String(nextResult.responseClass || "UNKNOWN")
          .replace(/[^a-z0-9_-]/gi, "_")
          .slice(0, 80)
          .toUpperCase(),
      };
    },
    async finish() {
      if (finished) return;
      finished = true;
      await writeRecord({
        schemaVersion: "civicos-server-experiment-span-v1",
        experimentId: "E3-E5",
        workflow: "vote_service",
        runId,
        startedAt,
        completedAt: new Date().toISOString(),
        durationMs: roundMs(performance.now() - startedAtMonotonic),
        outcome: result?.success ? "success" : "failure",
        responseClass: result?.responseClass || "ROUTE_EXIT_BEFORE_SERVICE_RESULT",
        stages,
      });
    },
  };
};

export default createVoteExperimentSpanCollector;
