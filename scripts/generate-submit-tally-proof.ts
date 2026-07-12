#!/usr/bin/env bun
process.env.ILAND_ENV_VALIDATION_SCOPE = "supabase-admin-script";

type ParsedArgs = {
  pollId: string | null;
  output: string | null;
  submit: boolean;
};

const usage = `Usage:
  bun scripts/generate-submit-tally-proof.ts --poll-id=<poll uuid> [--output=<file>] [--submit]

What it does:
  - Generates the Groth16 tally proof locally using the pinned tally artifacts.
  - Writes the proof envelope to tmp/tally-proofs by default.
  - With --submit, verifies and records the proof in Supabase using the same
    backend tally-proof service. It does not publish anything on-chain.

Useful env:
  SUPABASE_URL
  SUPABASE_SERVICE_ROLE_KEY
  ZKP_GROTH16_TALLY_PROVER_TIMEOUT_MS=300000
  ZKP_GROTH16_TALLY_PROVER_NODE_MAX_OLD_SPACE_MB=4096`;

const parseArgs = (argv: string[]): ParsedArgs => {
  const parsed: ParsedArgs = {
    pollId: null,
    output: null,
    submit: false,
  };

  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") {
      console.log(usage);
      process.exit(0);
    }
    if (arg === "--submit") {
      parsed.submit = true;
      continue;
    }
    if (arg.startsWith("--poll-id=")) {
      parsed.pollId = arg.slice("--poll-id=".length).trim() || null;
      continue;
    }
    if (arg.startsWith("--output=")) {
      parsed.output = arg.slice("--output=".length).trim() || null;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
};

const assertPollId = (pollId: string | null): string => {
  if (
    !pollId ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
      pollId,
    )
  ) {
    throw new Error("Missing or invalid --poll-id=<poll uuid>.");
  }
  return pollId;
};

const main = async () => {
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const { dirname, join, resolve } = await import("node:path");
  const { performance } = await import("node:perf_hooks");
  const { pollRepository } = await import("../src/repositories/pollRepository");
  const { groth16TallyProverService } = await import(
    "../src/services/groth16TallyProverService"
  );
  const { pollPublicAuditService } = await import(
    "../src/services/pollPublicAuditService"
  );

  const args = parseArgs(Bun.argv.slice(2));
  const pollId = assertPollId(args.pollId);
  const poll = await pollRepository.getById(pollId);
  if (!poll) {
    throw new Error(`Poll not found: ${pollId}`);
  }
  if (!poll.created_by_user_id) {
    throw new Error(`Poll ${pollId} has no owner; cannot submit tally proof.`);
  }

  const options = await pollRepository.getOptionsByPollId(poll.id);
  const startedAt = performance.now();
  console.log(`Generating Groth16 tally proof for poll ${poll.id}...`);
  const generated = await groth16TallyProverService.generateProofForPoll({
    poll,
    options,
  });
  const elapsedMs = Math.round(performance.now() - startedAt);
  if (!generated.success) {
    throw new Error(
      `Tally proof generation failed [${generated.errorCode}]: ${generated.message}`,
    );
  }

  const outputPath = resolve(
    args.output ||
      join(
        "tmp",
        "tally-proofs",
        `${poll.id}-${new Date().toISOString().replace(/[:.]/gu, "-")}.json`,
      ),
  );
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(generated.proof, null, 2)}\n`);

  console.log("Generated tally proof:");
  console.log(`  pollId=${poll.id}`);
  console.log(`  acceptedVoteCount=${generated.acceptedVoteCount}`);
  console.log(`  publicInputsHash=${generated.proof.publicInputsHash}`);
  console.log(`  elapsedMs=${elapsedMs}`);
  console.log(`  output=${outputPath}`);

  if (!args.submit) {
    console.log("");
    console.log("Proof was not submitted. Re-run with --submit to record it.");
    return;
  }

  const submitted = await pollPublicAuditService.submitTallyProof({
    pollId: poll.id,
    viewerUserId: poll.created_by_user_id,
    proof: generated.proof,
  });
  if (!submitted.success) {
    throw new Error(
      `Tally proof submission failed [${submitted.errorCode}]: ${submitted.message}`,
    );
  }

  console.log("Submitted and recorded tally proof:");
  console.log(`  resultHash=${submitted.tallyProof.resultHash}`);
  console.log(`  tallyProofHash=${submitted.tallyProof.tallyProofHash}`);
  console.log(`  verifiedAt=${submitted.tallyProof.verifiedAt}`);
  console.log("");
  console.log(
    "Next: publish audit from the app again. Railway will skip local proof generation because the verified tally proof is already recorded.",
  );
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
