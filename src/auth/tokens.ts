import { createHash, randomBytes } from "node:crypto";

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

// These opaque tokens are for the first-party iLand app session layer in
// `back/`. They are not the final external OIDC token format. Raw bearer
// tokens are never stored server-side; only their hashes are persisted.
const createOpaqueToken = (): string => randomBytes(32).toString("base64url");

export const createOpaqueBearerToken = () => {
  const token = createOpaqueToken();
  return {
    token,
    tokenHash: sha256Hex(token),
  };
};

export const hashOpaqueBearerToken = (token: string): string => sha256Hex(token);

export default {
  createOpaqueBearerToken,
  hashOpaqueBearerToken,
};
