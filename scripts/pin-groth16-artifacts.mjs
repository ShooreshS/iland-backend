#!/usr/bin/env node

import { copyFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const backendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const circuitRoot = resolve(backendRoot, "zkp/circuits");
const buildDir = resolve(circuitRoot, "build");
const defaultFinalDir = resolve(
  backendRoot,
  "scripts/human-ceremony/final",
);

const args = process.argv.slice(2);
const getArg = (name, fallback = null) => {
  const prefix = `${name}=`;
  const entry = args.find((arg) => arg.startsWith(prefix));
  return entry ? entry.slice(prefix.length) : fallback;
};
const hasArg = (name) => args.includes(name);

const profile = getArg("--profile", process.env.CIVICOS_GROTH16_ARTIFACT_PROFILE || "production");
const sourceDir = resolve(
  getArg(
    "--source-dir",
    profile === "internal-rc" ? buildDir : defaultFinalDir,
  ),
);
const dryRun = hasArg("--dry-run");
const skipProofs = hasArg("--skip-proofs");
const skipEnvPrint = hasArg("--skip-env-print");

const usage = () => {
  console.log(`Usage:
  node scripts/pin-groth16-artifacts.mjs --profile=internal-rc [--dry-run]
  node scripts/pin-groth16-artifacts.mjs --profile=production --source-dir=scripts/human-ceremony/final

What it does:
  1. Copies final zkeys/vkeys into zkp/circuits/build when source-dir differs.
  2. Regenerates proof vectors, Phase-2 transcripts, artifact manifests, and fixtures.
  3. Runs backend artifact env printing and Phase 9 readiness.

Production mode requires the ceremony env expected by the manifest writer:
  CIVICOS_GROTH16_CONTRIBUTORS or CIVICOS_GROTH16_CONTRIBUTORS_JSON
  CIVICOS_GROTH16_BEACON_SOURCE
  CIVICOS_GROTH16_BEACON_VALUE

Internal-RC mode rehearses the same pinning pipeline without the >=3 contributor
production gate. It does not run the human ceremony.
`);
};

if (hasArg("--help") || hasArg("-h")) {
  usage();
  process.exit(0);
}

if (profile !== "internal-rc" && profile !== "production") {
  throw new Error("--profile must be internal-rc or production.");
}

const circuitArtifacts = Object.freeze([
  {
    circuit: "credential_commitment_vote",
    files: [
      "credential_commitment_vote_final.zkey",
      "credential_commitment_vote.vkey.json",
    ],
  },
  {
    circuit: "encrypted_choice_tally",
    files: [
      "encrypted_choice_tally_final.zkey",
      "encrypted_choice_tally.vkey.json",
    ],
  },
]);

const run = (label, command, commandArgs, options = {}) => {
  const printable = [command, ...commandArgs].join(" ");
  console.log(`\n[phase9-pin] ${label}`);
  console.log(`[phase9-pin] $ ${printable}`);
  if (dryRun) {
    return;
  }
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd || backendRoot,
    env: {
      ...process.env,
      CIVICOS_GROTH16_ARTIFACT_PROFILE: profile,
      CIVICOS_GROTH16_TRANSCRIPT_GENERATED_AT:
        process.env.CIVICOS_GROTH16_TRANSCRIPT_GENERATED_AT ||
        new Date().toISOString(),
      CIVICOS_GROTH16_MANIFEST_GENERATED_AT:
        process.env.CIVICOS_GROTH16_MANIFEST_GENERATED_AT ||
        process.env.CIVICOS_GROTH16_TRANSCRIPT_GENERATED_AT ||
        new Date().toISOString(),
    },
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`${label} failed with exit code ${result.status}.`);
  }
};

const copyFinalArtifacts = () => {
  mkdirSync(buildDir, { recursive: true });

  for (const entry of circuitArtifacts) {
    for (const file of entry.files) {
      const source = resolve(sourceDir, file);
      const destination = resolve(buildDir, file);
      if (!existsSync(source)) {
        throw new Error(`Missing ${entry.circuit} artifact: ${source}`);
      }
      if (source === destination) {
        console.log(`[phase9-pin] using existing build artifact ${file}`);
        continue;
      }
      console.log(`[phase9-pin] copy ${source} -> ${destination}`);
      if (!dryRun) {
        copyFileSync(source, destination);
      }
    }
  }
};

const assertProductionEnv = () => {
  if (profile !== "production") {
    return;
  }
  const contributors =
    process.env.CIVICOS_GROTH16_CONTRIBUTORS ||
    process.env.CIVICOS_GROTH16_CONTRIBUTORS_JSON ||
    "";
  const contributorCount = process.env.CIVICOS_GROTH16_CONTRIBUTORS_JSON
    ? JSON.parse(process.env.CIVICOS_GROTH16_CONTRIBUTORS_JSON).length
    : contributors
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean).length;
  if (contributorCount < 3) {
    throw new Error(
      "Production pinning requires at least three contributors in CIVICOS_GROTH16_CONTRIBUTORS or CIVICOS_GROTH16_CONTRIBUTORS_JSON.",
    );
  }
  if (!process.env.CIVICOS_GROTH16_BEACON_SOURCE) {
    throw new Error("Production pinning requires CIVICOS_GROTH16_BEACON_SOURCE.");
  }
  if (!process.env.CIVICOS_GROTH16_BEACON_VALUE) {
    throw new Error("Production pinning requires CIVICOS_GROTH16_BEACON_VALUE.");
  }
};

assertProductionEnv();
copyFinalArtifacts();

if (!skipProofs) {
  run("generate and verify proof vectors", "npm", ["run", "prove:dev"], {
    cwd: circuitRoot,
  });
}
run("write Phase-2 transcripts", "npm", ["run", "transcripts"], {
  cwd: circuitRoot,
});
run("write artifact manifests", "npm", ["run", "manifests"], {
  cwd: circuitRoot,
});
run("write backend proof fixtures", "npm", ["run", "fixtures"], {
  cwd: circuitRoot,
});

if (!skipEnvPrint) {
  run("print backend env pins", "bun", ["run", "zkp:env"], {
    cwd: backendRoot,
  });
}
run("check Phase 9 readiness", "bun", ["run", "phase9:readiness"], {
  cwd: backendRoot,
});

if (!dryRun) {
  const voteManifest = JSON.parse(
    readFileSync(
      resolve(
        backendRoot,
        "src/zkp-artifacts/groth16-vote/credential_commitment_vote.manifest.json",
      ),
      "utf8",
    ),
  );
  const tallyManifest = JSON.parse(
    readFileSync(
      resolve(
        backendRoot,
        "src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest.json",
      ),
      "utf8",
    ),
  );
  console.log("\n[phase9-pin] completed");
  console.log(`[phase9-pin] vote transcript=${voteManifest.trustedSetupTranscriptHash}`);
  console.log(`[phase9-pin] tally transcript=${tallyManifest.trustedSetupTranscriptHash}`);
}
