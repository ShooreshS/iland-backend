import {
  createPublicKey,
  createVerify,
  type KeyObject,
} from "node:crypto";
import buildCanonicalAuthChallengePayload from "./challengePayload";
import type { AuthChallengePurpose, AuthCredentialPlatform } from "../types/db";

type VerifyCredentialSignatureInput = {
  publicKeyPem: string;
  challengeId: string;
  challenge: string;
  purpose: AuthChallengePurpose;
  platform: AuthCredentialPlatform;
  signature: string;
};

type VerifyCredentialSignatureResult =
  | {
      success: true;
      signatureEncoding: "base64-der" | "base64url-der" | "hex-der" | "base64-p1363" | "base64url-p1363" | "hex-p1363";
      payload: string;
    }
  | {
      success: false;
      errorCode:
        | "INVALID_PUBLIC_KEY"
        | "INVALID_SIGNATURE_ENCODING"
        | "INVALID_SIGNATURE";
      message: string;
    };

type DecodedSignatureCandidate = {
  bytes: Buffer;
  encoding:
    | "base64-der"
    | "base64url-der"
    | "hex-der"
    | "base64-p1363"
    | "base64url-p1363"
    | "hex-p1363";
  dsaEncoding: "der" | "ieee-p1363";
};

const normalizeBase64 = (value: string) => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = normalized.length % 4;
  return remainder === 0 ? normalized : `${normalized}${"=".repeat(4 - remainder)}`;
};

const decodeSignatureCandidates = (
  signature: string,
): DecodedSignatureCandidate[] => {
  const trimmed = signature.trim();
  const candidates: DecodedSignatureCandidate[] = [];

  const maybePush = (
    bytes: Buffer,
    encoding: DecodedSignatureCandidate["encoding"],
    dsaEncoding: DecodedSignatureCandidate["dsaEncoding"],
  ) => {
    if (bytes.length > 0) {
      candidates.push({
        bytes,
        encoding,
        dsaEncoding,
      });
    }
  };

  if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
    const bytes = Buffer.from(trimmed, "hex");
    maybePush(bytes, bytes.length === 64 ? "hex-p1363" : "hex-der", bytes.length === 64 ? "ieee-p1363" : "der");
  }

  const base64Bytes = Buffer.from(trimmed, "base64");
  maybePush(
    base64Bytes,
    base64Bytes.length === 64 ? "base64-p1363" : "base64-der",
    base64Bytes.length === 64 ? "ieee-p1363" : "der",
  );

  const base64UrlBytes = Buffer.from(normalizeBase64(trimmed), "base64");
  maybePush(
    base64UrlBytes,
    base64UrlBytes.length === 64 ? "base64url-p1363" : "base64url-der",
    base64UrlBytes.length === 64 ? "ieee-p1363" : "der",
  );

  return candidates.filter(
    (candidate, index, array) =>
      array.findIndex(
        (other) =>
          other.encoding === candidate.encoding &&
          other.bytes.equals(candidate.bytes) &&
          other.dsaEncoding === candidate.dsaEncoding,
      ) === index,
  );
};

const loadP256PublicKey = (
  publicKeyPem: string,
):
  | {
      success: true;
      keyObject: KeyObject;
    }
  | {
      success: false;
      errorCode: "INVALID_PUBLIC_KEY";
      message: string;
    } => {
  try {
    const keyObject = createPublicKey(publicKeyPem);
    if (keyObject.asymmetricKeyType !== "ec") {
      return {
        success: false,
        errorCode: "INVALID_PUBLIC_KEY",
        message: "Authentication credential public key must be an EC public key.",
      };
    }

    const namedCurve = keyObject.asymmetricKeyDetails?.namedCurve;
    if (namedCurve && namedCurve !== "prime256v1" && namedCurve !== "P-256") {
      return {
        success: false,
        errorCode: "INVALID_PUBLIC_KEY",
        message: "Authentication credential public key must use the P-256 curve.",
      };
    }

    return {
      success: true,
      keyObject,
    };
  } catch {
    return {
      success: false,
      errorCode: "INVALID_PUBLIC_KEY",
      message: "Authentication credential public key PEM could not be parsed.",
    };
  }
};

export const verifyCredentialSignature = (
  input: VerifyCredentialSignatureInput,
): VerifyCredentialSignatureResult => {
  const keyResult = loadP256PublicKey(input.publicKeyPem);
  if (!keyResult.success) {
    return keyResult;
  }

  const payload = buildCanonicalAuthChallengePayload({
    challengeId: input.challengeId,
    challenge: input.challenge,
    purpose: input.purpose,
    platform: input.platform,
  });
  const signatureCandidates = decodeSignatureCandidates(input.signature);
  if (signatureCandidates.length === 0) {
    return {
      success: false,
      errorCode: "INVALID_SIGNATURE_ENCODING",
      message: "Credential signature could not be decoded from hex, base64, or base64url.",
    };
  }

  for (const candidate of signatureCandidates) {
    try {
      const verifier = createVerify("sha256");
      verifier.update(payload, "utf8");
      verifier.end();

      const verified = verifier.verify(
        {
          key: keyResult.keyObject,
          dsaEncoding: candidate.dsaEncoding,
        },
        candidate.bytes,
      );

      if (verified) {
        return {
          success: true,
          signatureEncoding: candidate.encoding,
          payload,
        };
      }
    } catch {
      continue;
    }
  }

  return {
    success: false,
    errorCode: "INVALID_SIGNATURE",
    message:
      "Credential signature did not verify against the canonical challenge payload and enrolled P-256 public key.",
  };
};

export default verifyCredentialSignature;
