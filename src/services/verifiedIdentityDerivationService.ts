import { createHmac } from "node:crypto";

export const SUPPORTED_IDENTITY_NORMALIZATION_VERSIONS = [1] as const;
const SUPPORTED_IDENTITY_NORMALIZATION_VERSION_SET = new Set<number>(
  SUPPORTED_IDENTITY_NORMALIZATION_VERSIONS,
);
const NIDNH_HEX_PATTERN = /^[0-9a-f]{128}$/i;

export const normalizeNidnh = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 ? normalized : null;
};

export const isValidNidnh = (value: unknown): value is string => {
  const normalized = normalizeNidnh(value);
  return Boolean(normalized && NIDNH_HEX_PATTERN.test(normalized));
};

export const isSupportedNormalizationVersion = (
  value: unknown,
): value is number =>
  Number.isInteger(value) &&
  SUPPORTED_IDENTITY_NORMALIZATION_VERSION_SET.has(value as number);

export const deriveCanonicalIdentityKey = (params: {
  nidnh: string;
  pepper: string;
}): string => {
  const normalizedNidnh = normalizeNidnh(params.nidnh);
  if (!normalizedNidnh || !NIDNH_HEX_PATTERN.test(normalizedNidnh)) {
    throw new Error("Invalid nidnh format. Expected a SHA-512 hex digest.");
  }

  const pepper = typeof params.pepper === "string" ? params.pepper : "";
  if (!pepper.trim()) {
    throw new Error("A non-empty verified identity pepper is required.");
  }

  return createHmac("sha256", pepper).update(normalizedNidnh).digest("hex");
};

