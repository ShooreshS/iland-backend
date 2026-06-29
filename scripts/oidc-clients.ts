#!/usr/bin/env bun
process.env.ILAND_ENV_VALIDATION_SCOPE = "supabase-admin-script";

type ParsedArgs = {
  options: Record<string, string | boolean>;
};

const usage = `Usage:
  bun run oidc:clients -- -f sso-clients/codeiland-web.json [--rotate-secret]
  bun run oidc:clients -- --file=sso-clients/codeiland-web.json [--secrets-file=sso-client-secrets/codeiland-web.json]

Input config is committed JSON. Generated secrets are written to sso-client-secrets/,
which is gitignored. Raw client secrets are stored only in that local output file;
Supabase stores only a hash.`;

const parseArgs = (argv: string[]): ParsedArgs => {
  const options: Record<string, string | boolean> = {};

  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];

    if (option === "-h" || option === "--help") {
      options.help = true;
      continue;
    }

    if (option === "-f") {
      const next = argv[index + 1];
      if (!next) {
        throw new Error("Missing value after -f.");
      }
      options.file = next;
      index += 1;
      continue;
    }

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

  return { options };
};

const stringOption = (
  options: Record<string, string | boolean>,
  name: string,
): string | undefined => {
  const value = options[name];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
};

const main = async () => {
  const { options } = parseArgs(Bun.argv.slice(2));
  if (options.help) {
    console.log(usage);
    return;
  }

  const configFilePath = stringOption(options, "file");
  if (!configFilePath) {
    throw new Error(`Missing -f/--file.\n\n${usage}`);
  }

  const { default: oidcClientRegistrationService } = await import(
    "../src/services/oidcClientRegistrationService"
  );

  const result = await oidcClientRegistrationService.register({
    configFilePath,
    secretsDirectoryPath: stringOption(options, "secrets-file"),
    rotateSecret: Boolean(options["rotate-secret"]),
  });

  console.log(
    JSON.stringify(
      {
        registered: true,
        ...result,
        nextStep: result.secretGenerated
          ? `Copy client_secret from ${result.secretFilePath} into the Code iLand Railway backend as OIDC_CLIENT_SECRET.`
          : "Existing active secret kept. Use --rotate-secret if you need a new one.",
      },
      null,
      2,
    ),
  );
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
