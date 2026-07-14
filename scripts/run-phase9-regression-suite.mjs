#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const backendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(backendRoot, "..");
const appRoot = resolve(repoRoot, "iland");
const circuitRoot = resolve(backendRoot, "zkp/circuits");
const defaultEvidencePath = resolve(
  backendRoot,
  "zkp/PHASE9_REGRESSION_EVIDENCE.json",
);

const args = process.argv.slice(2);
const getArg = (name, fallback = null) => {
  const prefix = `${name}=`;
  const entry = args.find((arg) => arg.startsWith(prefix));
  return entry ? entry.slice(prefix.length) : fallback;
};
const hasArg = (name) => args.includes(name);

const evidencePath = resolve(
  getArg("--evidence", process.env.CIVICOS_PHASE9_EVIDENCE_PATH || defaultEvidencePath),
);
const skipManualEvidence = hasArg("--skip-manual-evidence");
const skipDevnet = hasArg("--skip-devnet");
const dryRun = hasArg("--dry-run");

const failures = [];
const results = [];
const backendUnitTestEnv = {
  NODE_ENV: "test",
  AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS: "true",
  AUTH_REQUIRE_ATTESTED_SESSIONS_FOR_PROTECTED_ROUTES: "false",
  AUTH_IOS_TEAM_ID: "",
  AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS: "",
  AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON: "",
  AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL: "",
  AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: "",
  SOLANA_AUDIT_TRANSACTIONS_ENABLED: "false",
  SOLANA_AUDIT_REGISTRY_AUTHORITY: "",
  SOLANA_AUDIT_ROOT_PUBLISHER_PUBLIC_KEY: "",
  SOLANA_AUDIT_FEE_PAYER_PUBLIC_KEY: "",
  SOLANA_AUDIT_FEE_PAYER_SECRET_KEY: "",
  SOLANA_AUDIT_MAINNET_CONFIRMED: "false",
  POLL_MAP_REFRESH_WORKER_ENABLED: "false",
  MAP_ENABLE_ALL_POLLS_DEBUG: "false",
};

const run = (label, command, commandArgs, options = {}) => {
  const printable = [command, ...commandArgs].join(" ");
  console.log(`\n[phase9-regression] ${label}`);
  console.log(`[phase9-regression] $ ${printable}`);
  if (dryRun) {
    results.push({ label, status: "dry-run" });
    return;
  }
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd || backendRoot,
    env: { ...process.env, ...(options.env || {}) },
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.status !== 0) {
    failures.push(`${label} failed with exit code ${result.status}`);
    if (options.capture) {
      console.error(result.stdout || "");
      console.error(result.stderr || "");
    }
  }
  results.push({ label, status: result.status === 0 ? "pass" : "fail" });
};

const readEvidence = () => {
  if (!existsSync(evidencePath)) {
    return null;
  }
  return JSON.parse(readFileSync(evidencePath, "utf8"));
};

const requireManual = (condition, label, details = "") => {
  if (!condition) {
    failures.push(`${label}${details ? `: ${details}` : ""}`);
  }
  results.push({ label, status: condition ? "pass" : "fail" });
};

const requireDeviceProof = (evidence, key, label) => {
  const drill = evidence?.[key];
  requireManual(drill?.status === "pass", `${label} evidence is pass`);
  requireManual(
    Number(drill?.maxProveMs) > 0 && Number(drill?.maxProveMs) <= 10_000,
    `${label} max proving time is within 10s`,
    `maxProveMs=${drill?.maxProveMs ?? "missing"}`,
  );
  requireManual(
    drill?.proofShape === "valid" || drill?.backendAcceptedVote === true,
    `${label} proof shape/backend acceptance recorded`,
  );
};

run("Phase 9 readiness gate", "bun", ["run", "phase9:readiness"], {
  cwd: backendRoot,
});
run(
  "backend verifier/audit/custody tests",
  "bun",
  [
    "test",
    "src/services/groth16ArtifactManifestService.test.ts",
    "src/services/groth16ProofVerifierService.test.ts",
    "src/services/groth16TallyProofVerifierService.test.ts",
    "src/services/groth16TallyProverService.test.ts",
    "src/services/credentialRegistryService.test.ts",
    "src/services/credentialIssuanceService.test.ts",
    "src/services/pollVotingService.submitVote.test.ts",
    "src/services/pollPublicAuditService.test.ts",
    "src/services/ballotCustodyPolicyService.test.ts",
    "src/services/zkpReleasePolicyService.test.ts",
    "src/services/zkpSecurityPolicyService.test.ts",
    "src/services/phase7AcceptanceScript.test.ts",
  ],
  { cwd: backendRoot, env: backendUnitTestEnv },
);
run("backend typecheck", "bun", ["run", "typecheck"], { cwd: backendRoot });
run("circuit vectors", "npm", ["test"], { cwd: circuitRoot });
run("mobile artifact verification", "npm", ["run", "verify:zkp-mobile-artifacts"], {
  cwd: appRoot,
});
run(
  "mobile ZKP contract tests",
  "node",
  [
    "--test",
    "test/identitySecretPhase2.test.js",
    "test/zkProofInputsPhase3.test.js",
    "test/zkpPhase4NativeProver.test.js",
    "test/zkpPhase0FailClosed.test.js",
    "test/zkpPhase1PlaintextOption.test.js",
    "test/phase9AuditReceiptUi.test.js",
  ],
  { cwd: appRoot },
);

if (!skipDevnet && process.env.CIVICOS_PHASE9_RUN_DEVNET_ACCEPTANCE === "true") {
  run("devnet E2E acceptance", "bun", ["run", "phase7:acceptance"], {
    cwd: backendRoot,
    env: {
      CIVICOS_PHASE7_VERIFY_ONLY:
        process.env.CIVICOS_PHASE7_VERIFY_ONLY || "true",
    },
  });
}

if (!skipManualEvidence && !dryRun) {
  const evidence = readEvidence();
  requireManual(Boolean(evidence), "Phase 9 manual evidence file exists", evidencePath);
  if (evidence) {
    requireDeviceProof(evidence, "iosRealDeviceProof", "iOS real-device proof");
    requireDeviceProof(evidence, "androidRealDeviceProof", "Android real-device proof");
    requireManual(
      evidence.devnetE2E?.status === "pass" &&
        typeof evidence.devnetE2E?.transcriptPath === "string",
      "devnet E2E evidence is pass",
    );
    requireManual(
      evidence.recoveryDrill?.status === "pass" &&
        evidence.recoveryDrill?.sameNullifierAfterRestore === true &&
        evidence.recoveryDrill?.duplicateRejected === true &&
        Array.isArray(evidence.recoveryDrill?.platforms) &&
        evidence.recoveryDrill.platforms.includes("android") &&
        evidence.recoveryDrill.platforms.includes("second_device"),
      "recovery drill evidence proves restore -> same nullifier -> duplicate rejection on Android and a second device",
    );
    const custody = evidence.custodyDrill;
    requireManual(
      custody?.status === "pass" &&
        (
          (custody?.mode === "threshold_trustee_v1" &&
            custody?.backendCanDecryptBallots === false &&
            custody?.singleCredentialCanDecryptBallot === false) ||
          (custody?.mode === "operator_trusted_private_beta" &&
            custody?.publicSecretBallotClaimAllowed === false &&
            custody?.scope === "v0_1_claim_gate")
        ),
      "custody drill evidence matches the active release claim",
    );
  }
}

console.log("\n[phase9-regression] summary");
for (const result of results) {
  console.log(`- ${result.status}: ${result.label}`);
}

if (failures.length > 0) {
  console.error("\n[phase9-regression] blockers");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("\n[phase9-regression] OK");
