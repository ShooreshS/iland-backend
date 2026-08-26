import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const VERSION = "v1";

const decodeKey = (encodedKey: string): Buffer => {
  const key = Buffer.from(encodedKey.trim(), "base64");
  if (key.length !== 32) {
    throw new Error(
      "NOTIFICATION_TOKEN_ENCRYPTION_KEY must be a base64-encoded 32-byte key.",
    );
  }
  return key;
};

export const hashPushToken = (token: string): string =>
  createHash("sha256").update(token, "utf8").digest("hex");

export const encryptPushToken = (token: string, encodedKey: string): string => {
  const key = decodeKey(encodedKey);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(token, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv, tag, encrypted]
    .map((part) => (typeof part === "string" ? part : part.toString("base64url")))
    .join(".");
};

export const decryptPushToken = (
  ciphertext: string,
  encodedKey: string,
): string => {
  const [version, ivValue, tagValue, encryptedValue, ...extra] = ciphertext.split(".");
  if (
    version !== VERSION ||
    !ivValue ||
    !tagValue ||
    !encryptedValue ||
    extra.length > 0
  ) {
    throw new Error("Unsupported push-token ciphertext.");
  }

  const decipher = createDecipheriv(
    "aes-256-gcm",
    decodeKey(encodedKey),
    Buffer.from(ivValue, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedValue, "base64url")),
    decipher.final(),
  ]).toString("utf8");
};

export default {
  decryptPushToken,
  encryptPushToken,
  hashPushToken,
};
