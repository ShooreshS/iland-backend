import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { z } from "zod";

import defaultOidcClientRepository from "../repositories/oidcClientRepository";

const httpsOrLocalhostUrl = z
  .string()
  .url()
  .refine(
    (value) => {
      const url = new URL(value);
      return (
        url.protocol === "https:" ||
        url.hostname === "localhost" ||
        url.hostname === "127.0.0.1"
      );
    },
    {
      message: "URL must be https, localhost, or 127.0.0.1.",
    },
  );

export const oidcClientConfigSchema = z
  .object({
    client_id: z.string().trim().min(1),
    client_name: z.string().trim().min(1),
    client_type: z.enum(["confidential", "public"]),
    application_type: z.enum(["web", "native"]),
    sector_identifier: z.string().trim().min(1),
    allowed_scopes: z.array(z.string().trim().min(1)).min(1),
    default_scopes: z.array(z.string().trim().min(1)).min(1),
    redirect_uri: httpsOrLocalhostUrl,
    post_logout_redirect_uri: httpsOrLocalhostUrl.optional(),
    client_uri: httpsOrLocalhostUrl.optional(),
    logo_uri: httpsOrLocalhostUrl.optional(),
    tos_uri: httpsOrLocalhostUrl.optional(),
    policy_uri: httpsOrLocalhostUrl.optional(),
    access_token_ttl_seconds: z.number().int().min(60).max(3600).optional(),
    authorization_code_ttl_seconds: z.number().int().min(60).max(600).optional(),
    refresh_token_ttl_days: z.number().int().min(1).max(365).optional(),
  })
  .strict()
  .refine((input) => input.allowed_scopes.includes("openid"), {
    message: "allowed_scopes must include openid.",
    path: ["allowed_scopes"],
  })
  .refine(
    (input) =>
      input.default_scopes.every((scope) => input.allowed_scopes.includes(scope)),
    {
      message: "default_scopes must be a subset of allowed_scopes.",
      path: ["default_scopes"],
    },
  );

export type OidcClientConfig = z.infer<typeof oidcClientConfigSchema>;

type OidcClientRepositoryLike = Pick<
  typeof defaultOidcClientRepository,
  | "upsertClient"
  | "replaceRedirectUris"
  | "listActiveSecrets"
  | "insertSecret"
  | "revokeActiveSecrets"
>;

export type RegisterOidcClientInput = {
  configFilePath: string;
  secretsDirectoryPath?: string;
  rotateSecret?: boolean;
};

export type RegisterOidcClientResult = {
  clientId: string;
  clientDbId: string;
  secretGenerated: boolean;
  secretFilePath: string | null;
  redirectUri: string;
  postLogoutRedirectUri: string | null;
};

export type OidcClientRegistrationServiceDependencies = {
  oidcClientRepositoryLike?: OidcClientRepositoryLike;
  randomBytesFn?: (size: number) => Buffer;
  now?: () => Date;
};

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const generateClientSecret = (randomBytesForService: (size: number) => Buffer) =>
  `ciland_${randomBytesForService(32).toString("base64url")}`;

const defaultSecretsPathForConfig = (configFilePath: string): string =>
  join(dirname(dirname(configFilePath)), "sso-client-secrets", basename(configFilePath));

export const createOidcClientRegistrationService = (
  dependencies: OidcClientRegistrationServiceDependencies = {},
) => {
  const oidcClientRepository =
    dependencies.oidcClientRepositoryLike ?? defaultOidcClientRepository;
  const randomBytesForService = dependencies.randomBytesFn ?? randomBytes;
  const now = dependencies.now ?? (() => new Date());

  return {
    async readConfig(configFilePath: string): Promise<OidcClientConfig> {
      const raw = await readFile(configFilePath, "utf8");
      const parsedJson = JSON.parse(raw) as unknown;
      return oidcClientConfigSchema.parse(parsedJson);
    },

    async register(
      input: RegisterOidcClientInput,
    ): Promise<RegisterOidcClientResult> {
      const config = await this.readConfig(input.configFilePath);
      const client = await oidcClientRepository.upsertClient({
        client_id: config.client_id,
        client_name: config.client_name,
        client_type: config.client_type,
        application_type: config.application_type,
        status: "active",
        client_uri: config.client_uri ?? null,
        logo_uri: config.logo_uri ?? null,
        tos_uri: config.tos_uri ?? null,
        policy_uri: config.policy_uri ?? null,
        sector_identifier: config.sector_identifier,
        allowed_scopes: config.allowed_scopes,
        default_scopes: config.default_scopes,
        require_pkce: true,
        pkce_required_method: "S256",
        id_token_signed_response_alg: "RS256",
        access_token_ttl_seconds: config.access_token_ttl_seconds,
        authorization_code_ttl_seconds: config.authorization_code_ttl_seconds,
        refresh_token_ttl_days: config.refresh_token_ttl_days,
      });

      const redirectRows: Array<{
        usage: "redirect" | "post_logout";
        redirect_uri: string;
      }> = [
        {
          usage: "redirect" as const,
          redirect_uri: config.redirect_uri,
        },
      ];
      if (config.post_logout_redirect_uri) {
        redirectRows.push({
          usage: "post_logout" as const,
          redirect_uri: config.post_logout_redirect_uri,
        });
      }
      await oidcClientRepository.replaceRedirectUris(client.id, redirectRows);

      const activeSecrets = await oidcClientRepository.listActiveSecrets(client.id);
      const shouldGenerateSecret =
        config.client_type === "confidential" &&
        (input.rotateSecret || activeSecrets.length === 0);

      let secretFilePath: string | null = null;
      if (shouldGenerateSecret) {
        if (input.rotateSecret && activeSecrets.length > 0) {
          await oidcClientRepository.revokeActiveSecrets(
            client.id,
            "rotated_by_oidc_clients_cli",
          );
        }

        const clientSecret = generateClientSecret(randomBytesForService);
        await oidcClientRepository.insertSecret({
          clientDbId: client.id,
          secretHash: sha256Hex(clientSecret),
          label: `generated-${now().toISOString()}`,
        });

        secretFilePath =
          input.secretsDirectoryPath?.trim() ||
          defaultSecretsPathForConfig(input.configFilePath);
        await mkdir(dirname(secretFilePath), { recursive: true });
        await writeFile(
          secretFilePath,
          `${JSON.stringify(
            {
              client_id: config.client_id,
              client_secret: clientSecret,
              generated_at: now().toISOString(),
              set_in_codeiland_railway_as: "OIDC_CLIENT_SECRET",
            },
            null,
            2,
          )}\n`,
          {
            mode: 0o600,
          },
        );
      }

      return {
        clientId: client.client_id,
        clientDbId: client.id,
        secretGenerated: shouldGenerateSecret,
        secretFilePath,
        redirectUri: config.redirect_uri,
        postLogoutRedirectUri: config.post_logout_redirect_uri ?? null,
      };
    },
  };
};

export const oidcClientRegistrationService =
  createOidcClientRegistrationService();

export default oidcClientRegistrationService;
