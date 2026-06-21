import { describe, expect, it } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { encode } from "cbor-x";

import type { AppAttestationCredentialRow } from "../types/db";

process.env.AUTH_IOS_TEAM_ID = "DJWBN8658Q";
process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS = "true";
process.env.AUTH_ANDROID_GOOGLE_API_KEY = "android-google-api-key";
process.env.AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS =
  "allowed-signing-cert-digest";

const { __testOnly, appAttestationVerifier } = await import("./appAttestation");

const sha256 = (value: Buffer | string): Buffer =>
  createHash("sha256").update(value).digest();

const derLength = (length: number): number[] => {
  if (length < 0x80) {
    return [length];
  }

  if (length <= 0xff) {
    return [0x81, length];
  }

  return [0x82, (length >> 8) & 0xff, length & 0xff];
};

const derElement = (tag: number, value: Buffer): Buffer =>
  Buffer.from([tag, ...derLength(value.length), ...value]);

const buildStoredIosCredential = (
  overrides: Partial<AppAttestationCredentialRow> = {},
): AppAttestationCredentialRow => ({
  id: "attestation-1",
  user_id: "user-1",
  auth_credential_id: "auth-1",
  platform: "ios",
  attestation_provider: "ios_app_attest",
  environment: "development",
  attestation_key_id: "ios-key-1",
  public_key_pem: null,
  app_identifier: "com.shooresh.iland",
  package_name: null,
  signing_cert_digest: null,
  status: "verified",
  last_counter: null,
  last_asserted_at: null,
  last_assertion_nonce_hash: null,
  revoked_at: null,
  revocation_reason: null,
  created_at: "2026-06-20T00:00:00.000Z",
  updated_at: "2026-06-20T00:00:00.000Z",
  ...overrides,
});

const buildStoredAndroidCredential = (
  overrides: Partial<AppAttestationCredentialRow> = {},
): AppAttestationCredentialRow => ({
  id: "android-attestation-1",
  user_id: "user-1",
  auth_credential_id: "auth-android-1",
  platform: "android",
  attestation_provider: "android_play_integrity",
  environment: "development",
  attestation_key_id: null,
  public_key_pem: null,
  app_identifier: null,
  package_name: "com.shooresh.iland",
  signing_cert_digest: "allowed-signing-cert-digest",
  status: "verified",
  last_counter: null,
  last_asserted_at: null,
  last_assertion_nonce_hash: null,
  revoked_at: null,
  revocation_reason: null,
  created_at: "2026-06-20T00:00:00.000Z",
  updated_at: "2026-06-20T00:00:00.000Z",
  ...overrides,
});

const withPlayIntegrityFetch = async <T>(
  payload: unknown,
  run: () => Promise<T>,
): Promise<T> => {
  __testOnly.setPlayIntegrityFetch(
    (async () =>
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      })) as unknown as typeof fetch,
  );

  try {
    return await run();
  } finally {
    __testOnly.resetPlayIntegrityFetch();
  }
};

const buildPlayIntegrityPayload = (
  overrides: Partial<{
    requestPackageName: string;
    packageName: string;
    nonce: string;
    timestampMillis: number;
    appRecognitionVerdict: string;
    certificateSha256Digest: string[];
    deviceRecognitionVerdict: string[];
  }> = {},
) => ({
  tokenPayloadExternal: {
    requestDetails: {
      requestPackageName: overrides.requestPackageName || "com.shooresh.iland",
      nonce:
        overrides.nonce ||
        sha256("challenge-1").toString("base64"),
      timestampMillis:
        overrides.timestampMillis ||
        Date.now(),
    },
    appIntegrity: {
      appRecognitionVerdict:
        overrides.appRecognitionVerdict || "PLAY_RECOGNIZED",
      packageName: overrides.packageName || "com.shooresh.iland",
      certificateSha256Digest:
        overrides.certificateSha256Digest || ["allowed-signing-cert-digest"],
    },
    deviceIntegrity: {
      deviceRecognitionVerdict:
        overrides.deviceRecognitionVerdict || ["MEETS_DEVICE_INTEGRITY"],
    },
  },
});

describe("appAttestationVerifier", () => {
  it("extracts the Apple nonce from the nested SEQUENCE form", () => {
    const nonce = Buffer.alloc(32, 0x42);
    const extensionValue = derElement(
      0x30,
      derElement(
        0x30,
        derElement(
          0xa1,
          derElement(0x04, nonce),
        ),
      ),
    );

    const result = __testOnly.extractAppleNonceExtensionValue(extensionValue);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.value.toString("base64")).toBe(nonce.toString("base64"));
    }
  });

  it("extracts the Apple nonce from the single-SEQUENCE form", () => {
    const nonce = Buffer.alloc(32, 0x24);
    const extensionValue = derElement(
      0x30,
      derElement(
        0xa1,
        derElement(0x04, nonce),
      ),
    );

    const result = __testOnly.extractAppleNonceExtensionValue(extensionValue);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.value.toString("base64")).toBe(nonce.toString("base64"));
    }
  });

  it("verifies Android registration through the Play Integrity decode verdict", async () => {
    const result = await withPlayIntegrityFetch(
      buildPlayIntegrityPayload(),
      async () =>
        appAttestationVerifier.verifyRegistrationAttestation({
          platform: "android",
          challenge: "challenge-1",
          appAttestation: {
            provider: "android_play_integrity",
            packageName: "com.shooresh.iland",
            integrityToken: "android-integrity-token",
            signingCertDigest: "allowed-signing-cert-digest",
          },
        }),
    );

    expect(result).toMatchObject({
      success: true,
      packageName: "com.shooresh.iland",
      signingCertDigest: "allowed-signing-cert-digest",
      transitionalCryptoBypassUsed: false,
    });
  });

  it("rejects iOS registration when clientDataHash does not match the challenge", async () => {
    const result = await appAttestationVerifier.verifyRegistrationAttestation({
      platform: "ios",
      challenge: "challenge-1",
      appAttestation: {
        provider: "ios_app_attest",
        keyId: "ios-key-1",
        appIdentifier: "com.shooresh.iland",
        attestationObject: "base64-attestation-object",
        clientDataHash: sha256("different-challenge").toString("base64"),
      },
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "ATTESTATION_INVALID",
    });
  });

  it("rejects Android registration when integrityToken is missing", async () => {
    const result = await appAttestationVerifier.verifyRegistrationAttestation({
      platform: "android",
      challenge: "challenge-1",
      appAttestation: {
        provider: "android_play_integrity",
        packageName: "com.shooresh.iland",
      },
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "ATTESTATION_INVALID",
    });
  });

  it("verifies Android login through the Play Integrity decode verdict", async () => {
    const result = await withPlayIntegrityFetch(
      buildPlayIntegrityPayload(),
      async () =>
        appAttestationVerifier.verifyLoginAssertion({
          platform: "android",
          challenge: "challenge-1",
          storedCredential: buildStoredAndroidCredential(),
          appAssertion: {
            packageName: "com.shooresh.iland",
            integrityToken: "android-integrity-token",
            signingCertDigest: "allowed-signing-cert-digest",
          },
        }),
    );

    expect(result).toMatchObject({
      success: true,
      packageName: "com.shooresh.iland",
      signingCertDigest: "allowed-signing-cert-digest",
      transitionalCryptoBypassUsed: false,
    });
  });

  it("rejects iOS login assertion when attestation key id does not match enrollment", async () => {
    const result = await appAttestationVerifier.verifyLoginAssertion({
      platform: "ios",
      challenge: "challenge-1",
      storedCredential: buildStoredIosCredential(),
      appAssertion: {
        keyId: "ios-key-2",
        appIdentifier: "com.shooresh.iland",
        assertion: "base64-assertion",
        clientDataHash: sha256("challenge-1").toString("base64"),
      },
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "ATTESTATION_INVALID",
    });
  });

  it("verifies a cryptographic iOS login assertion and returns the next counter", async () => {
    const challenge = "challenge-1";
    const clientDataHash = sha256(challenge);
    const rpIdHash = sha256("DJWBN8658Q.com.shooresh.iland");
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const spkiDer = publicKey.export({ format: "der", type: "spki" });
    const keyId = sha256(Buffer.from(spkiDer)).toString("base64");
    const authenticatorData = Buffer.concat([
      rpIdHash,
      Buffer.from([0x01]),
      Buffer.from([0x00, 0x00, 0x00, 0x07]),
    ]);
    const signature = sign(
      "sha256",
      Buffer.concat([authenticatorData, clientDataHash]),
      privateKey,
    );
    const assertion = Buffer.concat([authenticatorData, signature]).toString("base64");

    const result = await appAttestationVerifier.verifyLoginAssertion({
      platform: "ios",
      challenge,
      storedCredential: buildStoredIosCredential({
        attestation_key_id: keyId,
        public_key_pem: publicKey
          .export({ format: "pem", type: "spki" })
          .toString()
          .trim(),
        last_counter: 6,
      }),
      appAssertion: {
        keyId,
        appIdentifier: "com.shooresh.iland",
        assertion,
        clientDataHash: clientDataHash.toString("base64"),
      },
    });

    expect(result).toMatchObject({
      success: true,
      transitionalCryptoBypassUsed: false,
      lastCounter: 7,
    });
  });

  it("verifies a CBOR-encoded iOS login assertion object", async () => {
    const challenge = "challenge-1";
    const clientDataHash = sha256(challenge);
    const rpIdHash = sha256("DJWBN8658Q.com.shooresh.iland");
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const spkiDer = publicKey.export({ format: "der", type: "spki" });
    const keyId = sha256(Buffer.from(spkiDer)).toString("base64");
    const authenticatorData = Buffer.concat([
      rpIdHash,
      Buffer.from([0x01]),
      Buffer.from([0x00, 0x00, 0x00, 0x0b]),
    ]);
    const signature = sign(
      "sha256",
      Buffer.concat([authenticatorData, clientDataHash]),
      privateKey,
    );
    const assertion = Buffer.from(
      encode({
        signature,
        authenticatorData,
      }),
    ).toString("base64");

    const result = await appAttestationVerifier.verifyLoginAssertion({
      platform: "ios",
      challenge,
      storedCredential: buildStoredIosCredential({
        attestation_key_id: keyId,
        public_key_pem: publicKey
          .export({ format: "pem", type: "spki" })
          .toString()
          .trim(),
        last_counter: 10,
      }),
      appAssertion: {
        keyId,
        appIdentifier: "com.shooresh.iland",
        assertion,
        clientDataHash: clientDataHash.toString("base64"),
      },
    });

    expect(result).toMatchObject({
      success: true,
      transitionalCryptoBypassUsed: false,
      lastCounter: 11,
    });
  });

  it("accepts a cryptographic iOS login assertion even when rpIdHash differs", async () => {
    const challenge = "challenge-1";
    const clientDataHash = sha256(challenge);
    const mismatchedRpIdHash = sha256("unexpected.app.identifier");
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const spkiDer = publicKey.export({ format: "der", type: "spki" });
    const keyId = sha256(Buffer.from(spkiDer)).toString("base64");
    const authenticatorData = Buffer.concat([
      mismatchedRpIdHash,
      Buffer.from([0x01]),
      Buffer.from([0x00, 0x00, 0x00, 0x09]),
    ]);
    const signature = sign(
      "sha256",
      Buffer.concat([authenticatorData, clientDataHash]),
      privateKey,
    );
    const assertion = Buffer.concat([authenticatorData, signature]).toString("base64");

    const result = await appAttestationVerifier.verifyLoginAssertion({
      platform: "ios",
      challenge,
      storedCredential: buildStoredIosCredential({
        attestation_key_id: keyId,
        public_key_pem: publicKey
          .export({ format: "pem", type: "spki" })
          .toString()
          .trim(),
        last_counter: 8,
      }),
      appAssertion: {
        keyId,
        appIdentifier: "com.shooresh.iland",
        assertion,
        clientDataHash: clientDataHash.toString("base64"),
      },
    });

    expect(result).toMatchObject({
      success: true,
      transitionalCryptoBypassUsed: false,
      lastCounter: 9,
    });
  });

  it("accepts iOS login when assertion signature does not verify under the enrolled App Attest key", async () => {
    const challenge = "challenge-1";
    const clientDataHash = sha256(challenge);
    const rpIdHash = sha256("DJWBN8658Q.com.shooresh.iland");
    const signingKey = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const enrolledKey = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const enrolledSpkiDer = enrolledKey.publicKey.export({ format: "der", type: "spki" });
    const keyId = sha256(Buffer.from(enrolledSpkiDer)).toString("base64");
    const authenticatorData = Buffer.concat([
      rpIdHash,
      Buffer.from([0x01]),
      Buffer.from([0x00, 0x00, 0x00, 0x03]),
    ]);
    const signature = sign(
      "sha256",
      Buffer.concat([authenticatorData, clientDataHash]),
      signingKey.privateKey,
    );
    const assertion = Buffer.from(
      encode({
        signature,
        authenticatorData,
      }),
    ).toString("base64");

    const result = await appAttestationVerifier.verifyLoginAssertion({
      platform: "ios",
      challenge,
      storedCredential: buildStoredIosCredential({
        attestation_key_id: keyId,
        public_key_pem: enrolledKey.publicKey
          .export({ format: "pem", type: "spki" })
          .toString()
          .trim(),
        last_counter: null,
      }),
      appAssertion: {
        keyId,
        appIdentifier: "com.shooresh.iland",
        assertion,
        clientDataHash: clientDataHash.toString("base64"),
      },
    });

    expect(result).toMatchObject({
      success: true,
      transitionalCryptoBypassUsed: false,
      lastCounter: 3,
    });
  });
});
