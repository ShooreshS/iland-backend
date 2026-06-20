import { describe, expect, it } from "bun:test";
import { createSign, generateKeyPairSync } from "node:crypto";
import buildCanonicalAuthChallengePayload from "./challengePayload";
import { verifyCredentialSignature } from "./credentialSignature";

const buildPayload = () =>
  buildCanonicalAuthChallengePayload({
    challengeId: "challenge-1",
    challenge: "raw-challenge-value-1",
    purpose: "login",
    platform: "ios",
  });

describe("verifyCredentialSignature", () => {
  it("verifies a DER-encoded base64 ECDSA signature", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const signer = createSign("sha256");
    signer.update(buildPayload(), "utf8");
    signer.end();
    const signature = signer.sign({
      key: privateKey,
      dsaEncoding: "der",
    });

    const result = verifyCredentialSignature({
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      challengeId: "challenge-1",
      challenge: "raw-challenge-value-1",
      purpose: "login",
      platform: "ios",
      signature: signature.toString("base64"),
    });

    expect(result.success).toBe(true);
  });

  it("verifies a P1363-encoded base64url ECDSA signature", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const signer = createSign("sha256");
    signer.update(buildPayload(), "utf8");
    signer.end();
    const signature = signer.sign({
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });

    const result = verifyCredentialSignature({
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      challengeId: "challenge-1",
      challenge: "raw-challenge-value-1",
      purpose: "login",
      platform: "ios",
      signature: signature
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, ""),
    });

    expect(result.success).toBe(true);
  });

  it("rejects a signature for the wrong challenge payload", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const signer = createSign("sha256");
    signer.update(buildPayload(), "utf8");
    signer.end();
    const signature = signer.sign({
      key: privateKey,
      dsaEncoding: "der",
    });

    const result = verifyCredentialSignature({
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      challengeId: "challenge-1",
      challenge: "different-raw-challenge-value",
      purpose: "login",
      platform: "ios",
      signature: signature.toString("base64"),
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "INVALID_SIGNATURE",
    });
  });
});
