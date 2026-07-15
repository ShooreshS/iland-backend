#!/usr/bin/env bun

process.env.ILAND_ENV_VALIDATION_SCOPE ||= "supabase-admin-script";

const readArgValue = (name: string): string | null => {
  const prefix = `${name}=`;
  const direct = process.argv.find((arg) => arg.startsWith(prefix));
  if (direct) {
    return direct.slice(prefix.length);
  }
  const index = process.argv.indexOf(name);
  if (index >= 0 && process.argv[index + 1]) {
    return process.argv[index + 1];
  }
  return null;
};

const parsePositiveInteger = (value: string | null, fallback: number): number => {
  if (!value) {
    return fallback;
  }
  const numeric = Number(value);
  return Number.isInteger(numeric) && numeric > 0 ? numeric : fallback;
};

const apply = process.argv.includes("--apply");
const limit = parsePositiveInteger(readArgValue("--limit"), 25);

if (!apply) {
  process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";
}

const { credentialRootPublisherService } = await import(
  "../src/services/credentialRootPublisherService"
);

try {
  const result = await credentialRootPublisherService.publishPendingCredentialRoots({
    dryRun: !apply,
    limit,
  });

  console.log(JSON.stringify(result, null, 2));
  if (!apply) {
    console.log(
      "\nDry run only. Re-run with --apply to publish pending credential roots on-chain.",
    );
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
