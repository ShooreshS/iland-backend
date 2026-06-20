import { describe, expect, it } from "bun:test";
import { appAttestationVerifier } from "./appAttestation";
import type { AppAttestationCredentialRow } from "../types/db";

const storedIosCredential: AppAttestationCredentialRow = {
  id: "attestation-1",
  user_id: "user-1",
  auth_credential_id: "auth-1",
  platform: "ios",
  attestation_provider: "ios_app_attest",
  environment: "development",
  attestation_key_id: "ios-key-1",
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
};

describe("appAttestationVerifier", () => {
  it("accepts the transitional iOS registration contract when app identity matches", () => {
    const result = appAttestationVerifier.verifyRegistrationAttestation({
      platform: "ios",
      challenge: "challenge-1",
      appAttestation: {
        provider: "ios_app_attest",
        keyId: "ios-key-1",
        appIdentifier: "com.shooresh.iland",
        attestationObject: "base64-attestation-object",
      },
    });

    expect(result.success).toBe(true);
  });

  it("rejects iOS registration when the bundle identifier does not match", () => {
    const result = appAttestationVerifier.verifyRegistrationAttestation({
      platform: "ios",
      challenge: "challenge-1",
      appAttestation: {
        provider: "ios_app_attest",
        keyId: "ios-key-1",
        appIdentifier: "com.example.otherapp",
        attestationObject: "base64-attestation-object",
      },
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "ATTESTATION_INVALID",
    });
  });

  it("rejects Android registration when integrityToken is missing", () => {
    const result = appAttestationVerifier.verifyRegistrationAttestation({
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

  it("rejects iOS login assertion when attestation key id does not match enrollment", () => {
    const result = appAttestationVerifier.verifyLoginAssertion({
      platform: "ios",
      challenge: "challenge-1",
      storedCredential: storedIosCredential,
      appAssertion: {
        keyId: "ios-key-2",
        appIdentifier: "com.shooresh.iland",
        assertion: "base64-assertion",
      },
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "ATTESTATION_INVALID",
    });
  });
});
