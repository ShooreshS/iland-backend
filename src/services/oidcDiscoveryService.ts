import authPolicy from "../auth/policy";
import defaultOidcSigningKeyRepository from "../repositories/oidcSigningKeyRepository";
import type { OidcSigningKeyRow } from "../types/db";
import {
  OIDC_SUPPORTED_CLAIMS,
  OIDC_SUPPORTED_SCOPES,
} from "./oidcClaimContract";

type PublicJwk = Record<string, unknown>;

type OidcSigningKeyRepositoryLike = Pick<
  typeof defaultOidcSigningKeyRepository,
  "listPublicSigningKeys"
>;

export type OidcDiscoveryServiceDependencies = {
  issuer?: string;
  now?: () => Date;
  oidcSigningKeyRepositoryLike?: OidcSigningKeyRepositoryLike;
};

const PRIVATE_JWK_MEMBERS = new Set([
  "d",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "oth",
  "k",
]);

const normalizeIssuer = (issuer: string): string =>
  issuer.length > 1 && issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;

const endpoint = (issuer: string, path: string): string =>
  `${normalizeIssuer(issuer)}${path}`;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const isUsableAt = (row: OidcSigningKeyRow, now: Date): boolean => {
  if (row.status !== "active" && row.status !== "retiring") {
    return false;
  }

  if (row.revoked_at) {
    return false;
  }

  const notBefore = Date.parse(row.not_before);
  if (Number.isFinite(notBefore) && now.getTime() < notBefore) {
    return false;
  }

  if (row.not_after) {
    const notAfter = Date.parse(row.not_after);
    if (Number.isFinite(notAfter) && now.getTime() >= notAfter) {
      return false;
    }
  }

  return true;
};

const toPublicJwk = (row: OidcSigningKeyRow): PublicJwk | null => {
  if (!isPlainObject(row.public_jwk)) {
    return null;
  }

  const publicJwk: PublicJwk = {};
  for (const [key, value] of Object.entries(row.public_jwk)) {
    if (!PRIVATE_JWK_MEMBERS.has(key)) {
      publicJwk[key] = value;
    }
  }

  // Intention:
  // JWKS consumers need stable key metadata. The DB stores these fields as
  // first-class columns so key rotation can be audited even if a seeded JWK
  // accidentally omits kid/use/alg.
  publicJwk.kid = row.kid;
  publicJwk.use = row.key_use;
  publicJwk.alg = row.algorithm;

  return publicJwk;
};

export const createOidcDiscoveryService = (
  dependencies: OidcDiscoveryServiceDependencies = {},
) => {
  const issuer = normalizeIssuer(dependencies.issuer ?? authPolicy.issuer);
  const now = dependencies.now ?? (() => new Date());
  const oidcSigningKeyRepository =
    dependencies.oidcSigningKeyRepositoryLike ?? defaultOidcSigningKeyRepository;

  return {
    getOpenIdConfiguration() {
      return {
        issuer,
        authorization_endpoint: endpoint(issuer, "/authorize"),
        token_endpoint: endpoint(issuer, "/token"),
        userinfo_endpoint: endpoint(issuer, "/userinfo"),
        jwks_uri: endpoint(issuer, "/jwks"),
        revocation_endpoint: endpoint(issuer, "/revoke"),
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        subject_types_supported: ["pairwise"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: [
          "client_secret_basic",
          "client_secret_post",
          "none",
        ],
        scopes_supported: [...OIDC_SUPPORTED_SCOPES] as string[],
        claims_supported: [...OIDC_SUPPORTED_CLAIMS] as string[],
        code_challenge_methods_supported: ["S256"],
        claims_parameter_supported: false,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        require_request_uri_registration: false,
        // Non-standard but explicit for our first RP integration docs.
        pkce_required: true,
      };
    },

    async getJwks() {
      const rows = await oidcSigningKeyRepository.listPublicSigningKeys();
      const effectiveNow = now();

      return {
        keys: rows
          .filter((row) => isUsableAt(row, effectiveNow))
          .map(toPublicJwk)
          .filter((jwk): jwk is PublicJwk => Boolean(jwk)),
      };
    },
  };
};

export const oidcDiscoveryService = createOidcDiscoveryService();

export default oidcDiscoveryService;
