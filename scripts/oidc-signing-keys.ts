#!/usr/bin/env bun
process.env.ILAND_ENV_VALIDATION_SCOPE = "supabase-admin-script";

type ParsedArgs = {
  command: string;
  options: Record<string, string | boolean>;
};

const usage = `Usage:
  bun scripts/oidc-signing-keys.ts generate [--kid=<kid>] [--private-key-ref=<env-var>]
  bun scripts/oidc-signing-keys.ts seed [--kid=<kid>] [--private-key-ref=<env-var>] [--retire-existing]
  bun scripts/oidc-signing-keys.ts list
  bun scripts/oidc-signing-keys.ts retire --kid=<kid>
  bun scripts/oidc-signing-keys.ts revoke --kid=<kid>

Notes:
  - generate prints a new private key and public JWK without touching the DB.
  - seed inserts the public JWK metadata into oidc_signing_keys and prints the
    private key value you must place in Railway under private_key_ref.
  - private keys are never stored in Supabase by this script.`;

const parseArgs = (argv: string[]): ParsedArgs => {
  const [command = "help", ...rawOptions] = argv;
  const options: Record<string, string | boolean> = {};

  for (const option of rawOptions) {
    if (!option.startsWith("--")) {
      throw new Error(`Unexpected positional argument: ${option}`);
    }

    const withoutPrefix = option.slice(2);
    const equalsIndex = withoutPrefix.indexOf("=");
    if (equalsIndex === -1) {
      options[withoutPrefix] = true;
    } else {
      options[withoutPrefix.slice(0, equalsIndex)] = withoutPrefix.slice(
        equalsIndex + 1,
      );
    }
  }

  return {
    command,
    options,
  };
};

const stringOption = (
  options: Record<string, string | boolean>,
  name: string,
): string | undefined => {
  const value = options[name];
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }

  return undefined;
};

const requiredStringOption = (
  options: Record<string, string | boolean>,
  name: string,
): string => {
  const value = stringOption(options, name);
  if (!value) {
    throw new Error(`Missing required --${name}=... option.`);
  }

  return value;
};

const printGeneratedKey = (input: {
  kid: string;
  privateKeyRef: string;
  privateKeyPem: string;
  publicJwk: Record<string, unknown>;
}) => {
  console.log("Generated OIDC RS256 signing key:");
  console.log(`  kid: ${input.kid}`);
  console.log(`  private_key_ref: ${input.privateKeyRef}`);
  console.log("");
  console.log("Set this Railway variable before issuing ID tokens with this key:");
  console.log(`${input.privateKeyRef}=`);
  console.log(input.privateKeyPem);
  console.log("");
  console.log("Public JWK:");
  console.log(JSON.stringify(input.publicJwk, null, 2));
};

const main = async () => {
  const { default: oidcSigningKeyService } = await import(
    "../src/services/oidcSigningKeyService"
  );
  const { command, options } = parseArgs(Bun.argv.slice(2));

  if (command === "help" || command === "--help" || command === "-h") {
    console.log(usage);
    return;
  }

  if (command === "generate") {
    const generated = oidcSigningKeyService.generate({
      kid: stringOption(options, "kid"),
      privateKeyRef: stringOption(options, "private-key-ref"),
    });
    printGeneratedKey(generated);
    return;
  }

  if (command === "seed") {
    const result = await oidcSigningKeyService.seed({
      kid: stringOption(options, "kid"),
      privateKeyRef: stringOption(options, "private-key-ref"),
      retireExistingActiveKeys: Boolean(options["retire-existing"]),
    });

    console.log("Seeded OIDC RS256 signing key metadata:");
    console.log(
      JSON.stringify(
        {
          kid: result.inserted.kid,
          status: result.inserted.status,
          private_key_ref: result.inserted.private_key_ref,
          not_before: result.inserted.not_before,
          retiredExistingKeyCount: result.retiredExistingKeys.length,
        },
        null,
        2,
      ),
    );
    console.log("");
    printGeneratedKey(result.generated);
    return;
  }

  if (command === "list") {
    const rows = await oidcSigningKeyService.list();
    console.log(
      JSON.stringify(
        rows.map((row) => ({
          kid: row.kid,
          status: row.status,
          algorithm: row.algorithm,
          private_key_ref: row.private_key_ref,
          not_before: row.not_before,
          not_after: row.not_after,
          activated_at: row.activated_at,
          retired_at: row.retired_at,
          revoked_at: row.revoked_at,
          created_at: row.created_at,
        })),
        null,
        2,
      ),
    );
    return;
  }

  if (command === "retire") {
    const kid = requiredStringOption(options, "kid");
    const row = await oidcSigningKeyService.retire(kid);
    if (!row) {
      throw new Error(`No OIDC signing key found for kid=${kid}`);
    }

    console.log(JSON.stringify({ kid: row.kid, status: row.status }, null, 2));
    return;
  }

  if (command === "revoke") {
    const kid = requiredStringOption(options, "kid");
    const row = await oidcSigningKeyService.revoke(kid);
    if (!row) {
      throw new Error(`No OIDC signing key found for kid=${kid}`);
    }

    console.log(JSON.stringify({ kid: row.kid, status: row.status }, null, 2));
    return;
  }

  throw new Error(`Unknown command: ${command}\n\n${usage}`);
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
