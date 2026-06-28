import {
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";

import defaultOidcSigningKeyRepository, {
  type NewOidcSigningKeyRow,
} from "../repositories/oidcSigningKeyRepository";
import type { OidcSigningKeyRow } from "../types/db";

type OidcSigningKeyRepositoryLike = Pick<
  typeof defaultOidcSigningKeyRepository,
  | "insert"
  | "listAllSigningKeys"
  | "retireActiveExcept"
  | "retireByKid"
  | "revokeByKid"
>;

export type GeneratedOidcSigningKey = {
  kid: string;
  privateKeyPem: string;
  privateKeyRef: string;
  publicJwk: Record<string, unknown>;
  notBefore: string;
};

export type SeedOidcSigningKeyInput = {
  kid?: string;
  privateKeyRef?: string;
  notBefore?: Date;
  retireExistingActiveKeys?: boolean;
};

export type SeedOidcSigningKeyResult = {
  generated: GeneratedOidcSigningKey;
  inserted: OidcSigningKeyRow;
  retiredExistingKeys: OidcSigningKeyRow[];
};

export type OidcSigningKeyServiceDependencies = {
  now?: () => Date;
  randomBytesFn?: (size: number) => Buffer;
  oidcSigningKeyRepositoryLike?: OidcSigningKeyRepositoryLike;
};

const toBase64Url = (value: Buffer): string => value.toString("base64url");

const pad = (value: number): string => String(value).padStart(2, "0");

const timestampForKid = (date: Date): string =>
  [
    date.getUTCFullYear(),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    "t",
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
    "z",
  ].join("");

const privateKeyRefForKid = (kid: string): string =>
  `OIDC_RS256_PRIVATE_KEY_${kid.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`;

const generateKid = (date: Date, randomBytesForService: (size: number) => Buffer) =>
  `rs256-${timestampForKid(date)}-${toBase64Url(randomBytesForService(6))}`;

const exportPublicJwk = (
  publicKeyPem: string,
  kid: string,
): Record<string, unknown> => {
  const rawJwk = createPublicKey(publicKeyPem).export({
    format: "jwk",
  }) as Record<string, unknown>;

  return {
    kty: rawJwk.kty,
    n: rawJwk.n,
    e: rawJwk.e,
    kid,
    use: "sig",
    alg: "RS256",
  };
};

export const createOidcSigningKeyService = (
  dependencies: OidcSigningKeyServiceDependencies = {},
) => {
  const now = dependencies.now ?? (() => new Date());
  const randomBytesForService = dependencies.randomBytesFn ?? randomBytes;
  const oidcSigningKeyRepository =
    dependencies.oidcSigningKeyRepositoryLike ?? defaultOidcSigningKeyRepository;

  return {
    generate(
      input: Omit<SeedOidcSigningKeyInput, "retireExistingActiveKeys"> = {},
    ): GeneratedOidcSigningKey {
      const effectiveNotBefore = input.notBefore ?? now();
      const kid = input.kid ?? generateKid(effectiveNotBefore, randomBytesForService);
      const privateKeyRef = input.privateKeyRef ?? privateKeyRefForKid(kid);
      const { publicKey, privateKey } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicExponent: 0x10001,
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      });

      return {
        kid,
        privateKeyPem: privateKey,
        privateKeyRef,
        publicJwk: exportPublicJwk(publicKey, kid),
        notBefore: effectiveNotBefore.toISOString(),
      };
    },

    async seed(input: SeedOidcSigningKeyInput = {}): Promise<SeedOidcSigningKeyResult> {
      const generated = this.generate(input);
      const newRow: NewOidcSigningKeyRow = {
        kid: generated.kid,
        key_use: "sig",
        algorithm: "RS256",
        status: "active",
        public_jwk: generated.publicJwk,
        private_key_ref: generated.privateKeyRef,
        not_before: generated.notBefore,
        activated_at: generated.notBefore,
      };

      const inserted = await oidcSigningKeyRepository.insert(newRow);
      const retiredExistingKeys = input.retireExistingActiveKeys
        ? await oidcSigningKeyRepository.retireActiveExcept(inserted.kid)
        : [];

      return {
        generated,
        inserted,
        retiredExistingKeys,
      };
    },

    async list(): Promise<OidcSigningKeyRow[]> {
      return oidcSigningKeyRepository.listAllSigningKeys();
    },

    async retire(kid: string): Promise<OidcSigningKeyRow | null> {
      return oidcSigningKeyRepository.retireByKid(kid);
    },

    async revoke(kid: string): Promise<OidcSigningKeyRow | null> {
      return oidcSigningKeyRepository.revokeByKid(kid);
    },
  };
};

export const oidcSigningKeyService = createOidcSigningKeyService();

export default oidcSigningKeyService;
