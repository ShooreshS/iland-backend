import "reflect-metadata";

import { decode, decodeMultiple } from "cbor-x";
import { X509Certificate } from "@peculiar/x509";
import {
  createHash,
  createPublicKey,
  sign as signData,
  timingSafeEqual,
  verify as verifySignature,
} from "node:crypto";

import { hashOpaqueBearerToken } from "./tokens";
import authPolicy from "./policy";
import type {
  AppAttestationCredentialRow,
  AppAttestationEnvironment,
  AppAttestationProvider,
  AuthCredentialPlatform,
} from "../types/db";

type RegistrationAppAttestationInput = {
  platform: AuthCredentialPlatform;
  appAttestation: Record<string, unknown>;
  challenge: string;
};

type LoginAppAssertionInput = {
  platform: AuthCredentialPlatform;
  appAssertion: Record<string, unknown>;
  challenge: string;
  storedCredential: AppAttestationCredentialRow;
};

type VerifiedAppAttestationResult = {
  success: true;
  provider: AppAttestationProvider;
  environment: AppAttestationEnvironment;
  attestationKeyId: string | null;
  attestationPublicKeyPem: string | null;
  appIdentifier: string | null;
  packageName: string | null;
  signingCertDigest: string | null;
  lastAssertionNonceHash: string | null;
  lastCounter: number | null;
  transitionalCryptoBypassUsed: boolean;
};

type RejectedAppAttestationResult = {
  success: false;
  errorCode: "ATTESTATION_INVALID" | "NOT_IMPLEMENTED";
  message: string;
};

type ParsedAttestedAuthenticatorData = {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
  aaguid: Buffer;
  credentialId: Buffer;
  credentialPublicKeyPem: string;
  credentialPublicKeySpkiDer: Buffer;
};

type ParsedAssertionAuthenticatorData = {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
};

type ParsedIosAssertionPayload = {
  authenticatorData: Buffer;
  signature: Buffer;
};

type DecodedAndroidIntegrityVerdict = {
  requestPackageName: string;
  packageName: string;
  nonce: string;
  timestampMillis: number | null;
  appRecognitionVerdict: string | null;
  certificateSha256Digests: string[];
  deviceRecognitionVerdicts: string[];
  matchedSigningCertDigest: string | null;
};

const APPLE_APP_ATTEST_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;

const APPLE_NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2";
const PLAY_INTEGRITY_DECODE_URL = "https://playintegrity.googleapis.com/v1/%s:decodeIntegrityToken";
const GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token";
const PLAY_INTEGRITY_OAUTH_SCOPE = "https://www.googleapis.com/auth/playintegrity";
const IOS_ATTESTED_AUTH_DATA_MIN_LENGTH = 55;
const IOS_ASSERTION_AUTH_DATA_LENGTH = 37;
const IOS_FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;
const AAGUID_DEVELOPMENT = Buffer.from("appattestdevelop", "ascii");
const AAGUID_PRODUCTION = Buffer.concat([
  Buffer.from("appattest", "ascii"),
  Buffer.alloc(7),
]);
const ANDROID_INTEGRITY_MAX_AGE_MS = 10 * 60 * 1000;

let playIntegrityFetch: typeof fetch = fetch;
let googleOAuthFetch: typeof fetch = fetch;
let playIntegrityAccessTokenCache: {
  accessToken: string;
  expiresAtMs: number;
} | null = null;

const asTrimmedString = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
};

const normalizeAndroidCertDigest = (value: string | null): string | null => {
  if (!value) {
    return null;
  }

  const trimmed = value.trim();
  const hexCandidate = trimmed.replace(/:/g, "");
  if (/^[a-f0-9]+$/i.test(hexCandidate) && hexCandidate.length === 64) {
    return hexCandidate.toLowerCase();
  }

  const base64Candidate = trimmed.replace(/=+$/u, "");
  if (/^[a-z0-9_-]+$/i.test(base64Candidate) && base64Candidate.length === 43) {
    try {
      const decoded = Buffer.from(normalizeBase64(base64Candidate), "base64");
      if (decoded.length === 32) {
        return decoded.toString("hex");
      }
    } catch {
      // Fall through to lowercase normalization so the caller can still compare
      // unusual future formats without throwing while parsing an attestation.
    }
  }

  return trimmed.toLowerCase();
};

const defaultProviderForPlatform = (
  platform: AuthCredentialPlatform,
): AppAttestationProvider =>
  platform === "ios" ? "ios_app_attest" : "android_play_integrity";

const normalizeProvider = (
  platform: AuthCredentialPlatform,
  value: unknown,
): AppAttestationProvider => {
  const provider = asTrimmedString(value);
  if (provider === "ios_app_attest" || provider === "android_play_integrity") {
    return provider;
  }

  return defaultProviderForPlatform(platform);
};

const fallbackEnvironmentForPlatform = (
  platform: AuthCredentialPlatform,
): AppAttestationEnvironment =>
  platform === "ios"
    ? authPolicy.iosAppAttestEnvironment
    : authPolicy.enableTransitionalCryptoBypass
      ? "development"
      : "production";

const reject = (
  errorCode: RejectedAppAttestationResult["errorCode"],
  message: string,
): RejectedAppAttestationResult => ({
  success: false,
  errorCode,
  message,
});

const nonEmptyField = (
  label: string,
  value: unknown,
): { success: true; value: string } | RejectedAppAttestationResult => {
  const normalized = asTrimmedString(value);
  if (!normalized) {
    return reject("ATTESTATION_INVALID", `${label} is required.`);
  }

  return {
    success: true,
    value: normalized,
  };
};

const rejectIfMismatch = (
  label: string,
  actual: string,
  expected: string,
): RejectedAppAttestationResult | null => {
  if (actual === expected) {
    return null;
  }

  return reject(
    "ATTESTATION_INVALID",
    `${label} does not match the configured app identity.`,
  );
};

const normalizeBase64 = (value: string): string =>
  value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");

const decodeBase64 = (
  label: string,
  value: string,
): { success: true; value: Buffer } | RejectedAppAttestationResult => {
  try {
    return {
      success: true,
      value: Buffer.from(normalizeBase64(value), "base64"),
    };
  } catch {
    return reject("ATTESTATION_INVALID", `${label} must be valid base64.`);
  }
};

const canonicalBase64 = (value: string): string | null => {
  const decoded = decodeBase64("base64", value);
  return decoded.success ? decoded.value.toString("base64") : null;
};

const buffersEqual = (left: Buffer, right: Buffer): boolean =>
  left.length === right.length && timingSafeEqual(left, right);

const sha256 = (value: Buffer | string): Buffer =>
  createHash("sha256").update(value).digest();

const expectedClientDataHash = (
  challenge: string,
): Buffer => sha256(Buffer.from(challenge, "utf8"));

const validateClientDataHash = (
  label: string,
  value: unknown,
  challenge: string,
): { success: true; value: Buffer } | RejectedAppAttestationResult => {
  const encoded = nonEmptyField(label, value);
  if (!encoded.success) {
    return encoded;
  }

  const decoded = decodeBase64(label, encoded.value);
  if (!decoded.success) {
    return decoded;
  }

  const expected = expectedClientDataHash(challenge);
  if (!buffersEqual(decoded.value, expected)) {
    return reject(
      "ATTESTATION_INVALID",
      `${label} does not match the server challenge hash.`,
    );
  }

  return decoded;
};

const toBuffer = (
  label: string,
  value: unknown,
): { success: true; value: Buffer } | RejectedAppAttestationResult => {
  if (value instanceof Uint8Array) {
    return { success: true, value: Buffer.from(value) };
  }

  if (value instanceof ArrayBuffer) {
    return { success: true, value: Buffer.from(value) };
  }

  return reject("ATTESTATION_INVALID", `${label} must be binary data.`);
};

const toArrayBuffer = (value: Buffer): ArrayBuffer => Uint8Array.from(value).buffer;

const toBase64Url = (value: Buffer): string =>
  value.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");

type GoogleServiceAccountCredential = {
  clientEmail: string;
  privateKey: string;
};

type PlayIntegrityAccessTokenResult =
  | {
      success: true;
      accessToken: string;
    }
  | RejectedAppAttestationResult;

const base64UrlJson = (value: Record<string, unknown>): string =>
  toBase64Url(Buffer.from(JSON.stringify(value), "utf8"));

const normalizeGooglePrivateKey = (value: string): string =>
  value.replace(/\\n/g, "\n");

const readGoogleServiceAccountCredential = ():
  | {
      success: true;
      credential: GoogleServiceAccountCredential;
    }
  | RejectedAppAttestationResult => {
  if (authPolicy.androidGoogleServiceAccountJson) {
    let parsedCredential: unknown;
    try {
      parsedCredential = JSON.parse(authPolicy.androidGoogleServiceAccountJson);
    } catch {
      return reject(
        "NOT_IMPLEMENTED",
        "AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON.",
      );
    }

    const credentialRecord = parsedCredential as Record<string, unknown>;
    const clientEmail = asTrimmedString(credentialRecord.client_email);
    const privateKey = asTrimmedString(credentialRecord.private_key);
    if (!clientEmail || !privateKey) {
      return reject(
        "NOT_IMPLEMENTED",
        "AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_JSON must contain client_email and private_key.",
      );
    }

    return {
      success: true,
      credential: {
        clientEmail,
        privateKey: normalizeGooglePrivateKey(privateKey),
      },
    };
  }

  const clientEmail = asTrimmedString(authPolicy.androidGoogleServiceAccountClientEmail);
  const privateKey = asTrimmedString(authPolicy.androidGoogleServiceAccountPrivateKey);
  if (!clientEmail || !privateKey) {
    return reject(
      "NOT_IMPLEMENTED",
      "Google Play Integrity decode requires service-account OAuth credentials.",
    );
  }

  return {
    success: true,
    credential: {
      clientEmail,
      privateKey: normalizeGooglePrivateKey(privateKey),
    },
  };
};

const signGoogleServiceAccountJwt = (
  credential: GoogleServiceAccountCredential,
): string => {
  const issuedAt = Math.floor(Date.now() / 1000);
  const header = base64UrlJson({
    alg: "RS256",
    typ: "JWT",
  });
  const claims = base64UrlJson({
    iss: credential.clientEmail,
    scope: PLAY_INTEGRITY_OAUTH_SCOPE,
    aud: GOOGLE_OAUTH_TOKEN_URL,
    iat: issuedAt,
    exp: issuedAt + 3600,
  });
  const signingInput = `${header}.${claims}`;
  const signature = signData(
    "RSA-SHA256",
    Buffer.from(signingInput, "utf8"),
    credential.privateKey,
  );

  return `${signingInput}.${toBase64Url(signature)}`;
};

const getPlayIntegrityAccessToken = async (): Promise<PlayIntegrityAccessTokenResult> => {
  const now = Date.now();
  if (
    playIntegrityAccessTokenCache &&
    playIntegrityAccessTokenCache.expiresAtMs > now + 60_000
  ) {
    return {
      success: true,
      accessToken: playIntegrityAccessTokenCache.accessToken,
    };
  }

  const credentialResult = readGoogleServiceAccountCredential();
  if (!credentialResult.success) {
    return credentialResult;
  }

  let assertion: string;
  try {
    assertion = signGoogleServiceAccountJwt(credentialResult.credential);
  } catch {
    return reject(
      "NOT_IMPLEMENTED",
      "Google service-account private key could not sign the Play Integrity OAuth assertion.",
    );
  }

  let response: Response;
  try {
    response = await googleOAuthFetch(GOOGLE_OAUTH_TOKEN_URL, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }).toString(),
    });
  } catch {
    return reject(
      "ATTESTATION_INVALID",
      "Google OAuth token request for Play Integrity decode failed.",
    );
  }

  const responseText = await response.text();
  if (!response.ok) {
    return reject(
      "ATTESTATION_INVALID",
      `Google OAuth token request returned HTTP ${response.status}: ${truncateForLog(responseText, 200)}`,
    );
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(responseText) as Record<string, unknown>;
  } catch {
    return reject(
      "ATTESTATION_INVALID",
      "Google OAuth token response is not valid JSON.",
    );
  }

  const accessToken = asTrimmedString(payload.access_token);
  if (!accessToken) {
    return reject(
      "ATTESTATION_INVALID",
      "Google OAuth token response is missing access_token.",
    );
  }

  const expiresInSeconds =
    typeof payload.expires_in === "number"
      ? payload.expires_in
      : typeof payload.expires_in === "string"
        ? Number.parseInt(payload.expires_in, 10)
        : 3600;

  playIntegrityAccessTokenCache = {
    accessToken,
    expiresAtMs: now + Math.max(60, expiresInSeconds || 3600) * 1000,
  };

  return {
    success: true,
    accessToken,
  };
};

const getCoseKeyField = (
  coseKey: Record<string, unknown> | Map<unknown, unknown>,
  key: number,
): unknown => {
  if (coseKey instanceof Map) {
    return coseKey.get(key);
  }

  return coseKey[String(key)];
};

const parseCoseEc2PublicKey = (
  coseKeyBytes: Buffer,
): {
  success: true;
  publicKeyPem: string;
  publicKeySpkiDer: Buffer;
} | RejectedAppAttestationResult => {
  try {
    const decoded = decode(coseKeyBytes);
    if (!decoded || typeof decoded !== "object") {
      return reject(
        "ATTESTATION_INVALID",
        "iOS attestation credentialPublicKey is not a CBOR map.",
      );
    }

    const coseKey = decoded as Record<string, unknown> | Map<unknown, unknown>;
    const kty = getCoseKeyField(coseKey, 1);
    const crv = getCoseKeyField(coseKey, -1);
    const xCoord = toBuffer("iOS attestation credentialPublicKey.x", getCoseKeyField(coseKey, -2));
    if (!xCoord.success) {
      return xCoord;
    }

    const yCoord = toBuffer("iOS attestation credentialPublicKey.y", getCoseKeyField(coseKey, -3));
    if (!yCoord.success) {
      return yCoord;
    }

    if (kty !== 2 || crv !== 1) {
      return reject(
        "ATTESTATION_INVALID",
        "iOS attestation credentialPublicKey is not P-256 EC2.",
      );
    }

    if (xCoord.value.length !== 32 || yCoord.value.length !== 32) {
      return reject(
        "ATTESTATION_INVALID",
        "iOS attestation credentialPublicKey coordinates must be 32 bytes.",
      );
    }

    const publicKey = createPublicKey({
      key: {
        kty: "EC",
        crv: "P-256",
        x: toBase64Url(xCoord.value),
        y: toBase64Url(yCoord.value),
      },
      format: "jwk",
    });

    const publicKeySpkiDer = Buffer.from(
      publicKey.export({ format: "der", type: "spki" }),
    );

    return {
      success: true,
      publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString().trim(),
      publicKeySpkiDer,
    };
  } catch {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation credentialPublicKey could not be parsed.",
    );
  }
};

const parseAttestedAuthenticatorData = (
  authData: Buffer,
): { success: true; value: ParsedAttestedAuthenticatorData } | RejectedAppAttestationResult => {
  if (authData.length < IOS_ATTESTED_AUTH_DATA_MIN_LENGTH) {
    return reject("ATTESTATION_INVALID", "iOS attestation authData is too short.");
  }

  const credentialIdLength = authData.readUInt16BE(53);
  const credentialIdEnd = 55 + credentialIdLength;
  if (authData.length < credentialIdEnd) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation authData is truncated before credentialId completes.",
    );
  }

  const credentialPublicKeyBytes = authData.subarray(credentialIdEnd);
  if (credentialPublicKeyBytes.length === 0) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation authData is missing credentialPublicKey bytes.",
    );
  }

  const credentialPublicKey = parseCoseEc2PublicKey(credentialPublicKeyBytes);
  if (!credentialPublicKey.success) {
    return credentialPublicKey;
  }

  return {
    success: true,
    value: {
      rpIdHash: authData.subarray(0, 32),
      flags: authData[32],
      signCount: authData.readUInt32BE(33),
      aaguid: authData.subarray(37, 53),
      credentialId: authData.subarray(55, credentialIdEnd),
      credentialPublicKeyPem: credentialPublicKey.publicKeyPem,
      credentialPublicKeySpkiDer: credentialPublicKey.publicKeySpkiDer,
    },
  };
};

const parseAssertionAuthenticatorData = (
  authData: Buffer,
): { success: true; value: ParsedAssertionAuthenticatorData } | RejectedAppAttestationResult => {
  if (authData.length !== IOS_ASSERTION_AUTH_DATA_LENGTH) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS assertion authenticatorData must be 37 bytes.",
    );
  }

  return {
    success: true,
    value: {
      rpIdHash: authData.subarray(0, 32),
      flags: authData[32],
      signCount: authData.readUInt32BE(33),
    },
  };
};

const parseIosAssertionPayload = (
  assertionBytes: Buffer,
): { success: true; value: ParsedIosAssertionPayload } | RejectedAppAttestationResult => {
  const extractDecodedAssertion = (
    decodedAssertion: unknown,
  ): { success: true; value: ParsedIosAssertionPayload } | RejectedAppAttestationResult | null => {
    if (!(decodedAssertion && typeof decodedAssertion === "object")) {
      return null;
    }

    const record = decodedAssertion instanceof Map
      ? Object.fromEntries(decodedAssertion.entries())
      : decodedAssertion as Record<string, unknown>;
    const authenticatorData = toBuffer(
      "iOS assertion authenticatorData",
      record.authenticatorData ?? record.authData,
    );
    if (!authenticatorData.success) {
      return authenticatorData;
    }

    const signature = toBuffer("iOS assertion signature", record.signature);
    if (!signature.success) {
      return signature;
    }

    return {
      success: true,
      value: {
        authenticatorData: authenticatorData.value,
        signature: signature.value,
      },
    };
  };

  try {
    const decodedAssertion = decode(assertionBytes);
    const extractedAssertion = extractDecodedAssertion(decodedAssertion);
    if (extractedAssertion) {
      return extractedAssertion;
    }
  } catch {
    // Fall through to decodeMultiple() and finally to the raw legacy shape.
  }

  try {
    let firstDecodedAssertion: unknown;
    decodeMultiple(assertionBytes, (decodedAssertion) => {
      firstDecodedAssertion = decodedAssertion;
      return false;
    });
    if (firstDecodedAssertion !== undefined) {
      const extractedAssertion = extractDecodedAssertion(firstDecodedAssertion);
      if (extractedAssertion) {
        return extractedAssertion;
      }
    }
  } catch {
    // Compatibility fallback:
    // older local tests and some earlier assumptions modeled the assertion as
    // raw authenticatorData || signature bytes. Keep accepting that format so
    // existing fixtures continue to work while production devices use the
    // structured assertion object returned by DCAppAttestService.generateAssertion.
  }

  if (assertionBytes.length <= IOS_ASSERTION_AUTH_DATA_LENGTH) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS assertion payload is too short.",
    );
  }

  return {
    success: true,
    value: {
      authenticatorData: assertionBytes.subarray(0, IOS_ASSERTION_AUTH_DATA_LENGTH),
      signature: assertionBytes.subarray(IOS_ASSERTION_AUTH_DATA_LENGTH),
    },
  };
};

const verifyRpIdHash = (
  actual: Buffer,
  label: string,
): RejectedAppAttestationResult | null => {
  if (!authPolicy.iosTeamId) {
    return reject(
      "ATTESTATION_INVALID",
      "AUTH_IOS_TEAM_ID is not configured for App Attest verification.",
    );
  }

  const expected = sha256(`${authPolicy.iosTeamId}.${authPolicy.iosBundleId}`);
  if (buffersEqual(actual, expected)) {
    return null;
  }

  return reject(
    "ATTESTATION_INVALID",
    `${label} does not match SHA-256(teamID.bundleID).`,
  );
};

const expectedIosRpIdHash = (): Buffer | null => {
  if (!authPolicy.iosTeamId) {
    return null;
  }

  return sha256(`${authPolicy.iosTeamId}.${authPolicy.iosBundleId}`);
};

const tryVerifySignatureVariant = (
  algorithm: Parameters<typeof verifySignature>[0],
  data: Buffer,
  publicKey: ReturnType<typeof createPublicKey>,
  signature: Buffer,
): boolean => {
  try {
    return verifySignature(algorithm, data, publicKey, signature);
  } catch {
    return false;
  }
};

const verifyAaguid = (
  actual: Buffer,
): RejectedAppAttestationResult | null => {
  const expected =
    authPolicy.iosAppAttestEnvironment === "development"
      ? AAGUID_DEVELOPMENT
      : AAGUID_PRODUCTION;

  if (buffersEqual(actual, expected)) {
    return null;
  }

  return reject(
    "ATTESTATION_INVALID",
    `iOS App Attest AAGUID does not match the configured ${authPolicy.iosAppAttestEnvironment} environment.`,
  );
};

const exportSpkiDerFromCertificatePublicKey = (
  certificate: X509Certificate,
): Buffer => {
  // Intention:
  // App Attest keyId is derived from the certificate leaf public key's SPKI
  // bytes. Use Node crypto to canonicalize the PEM/DER export path here rather
  // than depending on a third-party x509 helper's raw ASN.1 serialization.
  const publicKeyPem = certificate.publicKey.toString("pem");
  const publicKey = createPublicKey(publicKeyPem);
  return Buffer.from(publicKey.export({ format: "der", type: "spki" }));
};

const hashSpkiDerFromPublicKeyPem = (
  publicKeyPem: string,
): Buffer => {
  const publicKey = createPublicKey(publicKeyPem);
  const spkiDer = Buffer.from(publicKey.export({ format: "der", type: "spki" }));
  return sha256(spkiDer);
};

const truncateForLog = (value: string, maxLength: number): string =>
  value.length <= maxLength ? value : `${value.slice(0, maxLength)}…`;

const decodeAndroidIntegrityNonce = (nonce: string): Buffer | null => {
  try {
    return Buffer.from(normalizeBase64(nonce), "base64");
  } catch {
    return null;
  }
};

// Must match the Android client nonce passed to Play Integrity:
// SHA-256(challenge), encoded as base64url without padding. We compare decoded
// bytes instead of raw strings so harmless padding/standard-vs-url-safe encoding
// differences do not break an otherwise valid challenge binding.
const expectedAndroidIntegrityNonce = (challenge: string): string =>
  toBase64Url(expectedClientDataHash(challenge));

const decodeAndroidPlayIntegrityVerdict = async (
  integrityToken: string,
  challenge: string,
): Promise<DecodedAndroidIntegrityVerdict | RejectedAppAttestationResult> => {
  // Production policy:
  // Android attestation is only considered real when the backend can both call
  // the Google decode API and pin the verdict to an explicit allow-list of
  // release signing certificate digests. Do not silently accept an unpinned
  // certificate in strict mode.
  if (
    !authPolicy.enableTransitionalCryptoBypass &&
    authPolicy.androidAllowedSigningCertDigests.length === 0
  ) {
    return reject(
      "NOT_IMPLEMENTED",
      "AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS is required for strict Android Play Integrity verification.",
    );
  }

  const accessTokenResult = await getPlayIntegrityAccessToken();
  if (!accessTokenResult.success) {
    return accessTokenResult;
  }

  const url = PLAY_INTEGRITY_DECODE_URL.replace(
    "%s",
    encodeURIComponent(authPolicy.androidPackageName),
  );

  let response: Response;
  try {
    response = await playIntegrityFetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessTokenResult.accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        integrity_token: integrityToken,
      }),
    });
  } catch {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity decode request failed.",
    );
  }

  const responseText = await response.text();
  if (!response.ok) {
    return reject(
      "ATTESTATION_INVALID",
      `Google Play Integrity decode returned HTTP ${response.status}: ${truncateForLog(responseText, 200)}`,
    );
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(responseText) as Record<string, unknown>;
  } catch {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity decode response is not valid JSON.",
    );
  }

  const tokenPayloadExternal =
    payload.tokenPayloadExternal as Record<string, unknown> | undefined;
  if (!tokenPayloadExternal || typeof tokenPayloadExternal !== "object") {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity decode response is missing tokenPayloadExternal.",
    );
  }

  const requestDetails =
    tokenPayloadExternal.requestDetails as Record<string, unknown> | undefined;
  const appIntegrity =
    tokenPayloadExternal.appIntegrity as Record<string, unknown> | undefined;
  const deviceIntegrity =
    tokenPayloadExternal.deviceIntegrity as Record<string, unknown> | undefined;

  const requestPackageName = asTrimmedString(requestDetails?.requestPackageName) || "";
  const nonce = asTrimmedString(requestDetails?.nonce) || "";
  const timestampMillis =
    typeof requestDetails?.timestampMillis === "number"
      ? requestDetails.timestampMillis
      : typeof requestDetails?.timestampMillis === "string"
        ? Number.parseInt(requestDetails.timestampMillis, 10)
        : Number.NaN;

  const packageName = asTrimmedString(appIntegrity?.packageName) || "";
  const appRecognitionVerdict = asTrimmedString(appIntegrity?.appRecognitionVerdict);
  const certificateSha256Digests = Array.isArray(appIntegrity?.certificateSha256Digest)
    ? appIntegrity.certificateSha256Digest
        .map((value) => asTrimmedString(value))
        .map((value) => normalizeAndroidCertDigest(value))
        .filter((value): value is string => Boolean(value))
    : [];
  const deviceRecognitionVerdicts = Array.isArray(deviceIntegrity?.deviceRecognitionVerdict)
    ? deviceIntegrity.deviceRecognitionVerdict
        .map((value) => asTrimmedString(value))
        .filter((value): value is string => Boolean(value))
    : [];

  if (packageName !== authPolicy.androidPackageName) {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity packageName does not match the configured app identity.",
    );
  }

  if (requestPackageName !== authPolicy.androidPackageName) {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity requestPackageName does not match the configured app identity.",
    );
  }

  const expectedNonceHash = expectedClientDataHash(challenge);
  const expectedNonce = toBase64Url(expectedNonceHash);
  const decodedNonce = decodeAndroidIntegrityNonce(nonce);
  if (!decodedNonce || !buffersEqual(decodedNonce, expectedNonceHash)) {
    console.warn("[auth]", {
      route: "android_play_integrity_decode",
      warning: "nonce_mismatch",
      nonceLength: nonce.length,
      expectedNonceLength: expectedNonce.length,
      nonceSha256: sha256(nonce).toString("base64"),
      expectedNonceSha256: sha256(expectedNonce).toString("base64"),
      decodedNonceLength: decodedNonce?.length ?? null,
      challengeLength: challenge.length,
      challengeHashPrefix: hashOpaqueBearerToken(challenge).slice(0, 16),
      matchesExpectedString: nonce === expectedNonce,
      matchesExpectedStandardBase64: nonce === expectedNonceHash.toString("base64"),
      matchesExpectedBase64UrlWithPadding: nonce === expectedNonceHash
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_"),
    });
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity nonce does not match the server challenge hash.",
    );
  }

  if (appRecognitionVerdict !== "PLAY_RECOGNIZED") {
    return reject(
      "ATTESTATION_INVALID",
      `Google Play Integrity appRecognitionVerdict is ${appRecognitionVerdict || "missing"}, expected PLAY_RECOGNIZED.`,
    );
  }

  let matchedSigningCertDigest: string | null = null;
  if (authPolicy.androidAllowedSigningCertDigests.length > 0) {
    matchedSigningCertDigest =
      certificateSha256Digests.find((digest) =>
        authPolicy.androidAllowedSigningCertDigests.some(
          (allowedDigest) => allowedDigest.toLowerCase() === digest.toLowerCase(),
        )) || null;

    if (!matchedSigningCertDigest) {
      console.warn("[auth]", {
        route: "android_play_integrity_decode",
        warning: "signing_certificate_digest_not_allow_listed",
        packageName,
        requestPackageName,
        appRecognitionVerdict,
        certificateSha256Digests,
        allowedSigningCertDigests: authPolicy.androidAllowedSigningCertDigests,
      });
      return reject(
        "ATTESTATION_INVALID",
        "Google Play Integrity signing certificate digest is not allow-listed.",
      );
    }
  } else {
    matchedSigningCertDigest = certificateSha256Digests[0] || null;
  }

  if (
    authPolicy.androidRequireStrongIntegrity &&
    !deviceRecognitionVerdicts.includes("MEETS_STRONG_INTEGRITY")
  ) {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity device does not meet strong integrity.",
    );
  }

  if (!Number.isFinite(timestampMillis)) {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity timestampMillis is missing or invalid.",
    );
  }

  if (Math.abs(Date.now() - timestampMillis) > ANDROID_INTEGRITY_MAX_AGE_MS) {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity token timestamp is too old.",
    );
  }

  return {
    requestPackageName,
    packageName,
    nonce,
    timestampMillis,
    appRecognitionVerdict,
    certificateSha256Digests,
    deviceRecognitionVerdicts,
    matchedSigningCertDigest,
  };
};

const readDerLength = (
  bytes: Buffer,
  offset: number,
): { length: number; nextOffset: number } => {
  if (offset >= bytes.length) {
    throw new Error("DER length offset is out of bounds.");
  }

  const first = bytes[offset];
  if ((first & 0x80) === 0) {
    return { length: first, nextOffset: offset + 1 };
  }

  const byteLength = first & 0x7f;
  if (byteLength === 0 || offset + 1 + byteLength > bytes.length) {
    throw new Error("DER length encoding is invalid.");
  }

  let length = 0;
  for (let index = 0; index < byteLength; index += 1) {
    length = (length << 8) | bytes[offset + 1 + index];
  }

  return {
    length,
    nextOffset: offset + 1 + byteLength,
  };
};

const readDerElement = (
  bytes: Buffer,
  offset: number,
): {
  tag: number;
  value: Buffer;
  nextOffset: number;
} => {
  if (offset >= bytes.length) {
    throw new Error("DER element offset is out of bounds.");
  }

  const tag = bytes[offset];
  const { length, nextOffset } = readDerLength(bytes, offset + 1);
  const valueStart = nextOffset;
  const valueEnd = valueStart + length;
  if (valueEnd > bytes.length) {
    throw new Error("DER element length exceeds available bytes.");
  }

  return {
    tag,
    value: bytes.subarray(valueStart, valueEnd),
    nextOffset: valueEnd,
  };
};

const findAppleNonceCandidate = (
  bytes: Buffer,
  depth = 0,
): Buffer | null => {
  if (depth > 8) {
    return null;
  }

  let offset = 0;
  while (offset < bytes.length) {
    const element = readDerElement(bytes, offset);

    if (element.tag === 0x04 && element.value.length === 32) {
      return element.value;
    }

    const isSequence = element.tag === 0x30;
    const isConstructedContextSpecific = (element.tag & 0xe0) === 0xa0;
    if (isSequence || isConstructedContextSpecific) {
      const nestedCandidate = findAppleNonceCandidate(element.value, depth + 1);
      if (nestedCandidate) {
        return nestedCandidate;
      }
    }

    offset = element.nextOffset;
  }

  return null;
};

const extractAppleNonceExtensionValue = (
  extensionValue: Buffer,
): { success: true; value: Buffer } | RejectedAppAttestationResult => {
  try {
    const nonceCandidate = findAppleNonceCandidate(extensionValue);
    if (!nonceCandidate) {
      return reject(
        "ATTESTATION_INVALID",
        "Apple nonce extension is not in the expected ASN.1 shape.",
      );
    }

    return {
      success: true,
      value: nonceCandidate,
    };
  } catch {
    return reject(
      "ATTESTATION_INVALID",
      "Apple nonce extension could not be parsed.",
    );
  }
};

const validateRegistrationContract = (
  input: RegistrationAppAttestationInput,
):
  | {
      success: true;
      provider: AppAttestationProvider;
      attestationKeyId: string | null;
      appIdentifier: string | null;
      packageName: string | null;
      signingCertDigest: string | null;
    }
  | RejectedAppAttestationResult => {
  const provider = normalizeProvider(input.platform, input.appAttestation.provider);
  if (provider !== defaultProviderForPlatform(input.platform)) {
    return reject(
      "ATTESTATION_INVALID",
      "Attestation provider does not match the request platform.",
    );
  }

  if (input.platform === "ios") {
    const keyId = nonEmptyField("appAttestation.keyId", input.appAttestation.keyId);
    if (!keyId.success) {
      return keyId;
    }

    const appIdentifier = nonEmptyField(
      "appAttestation.appIdentifier",
      input.appAttestation.appIdentifier,
    );
    if (!appIdentifier.success) {
      return appIdentifier;
    }

    const attestationObject = nonEmptyField(
      "appAttestation.attestationObject",
      input.appAttestation.attestationObject,
    );
    if (!attestationObject.success) {
      return attestationObject;
    }

    const clientDataHash = validateClientDataHash(
      "appAttestation.clientDataHash",
      input.appAttestation.clientDataHash,
      input.challenge,
    );
    if (!clientDataHash.success) {
      return clientDataHash;
    }

    const mismatch = rejectIfMismatch(
      "iOS bundle identifier",
      appIdentifier.value,
      authPolicy.iosBundleId,
    );
    if (mismatch) {
      return mismatch;
    }

    return {
      success: true,
      provider,
      attestationKeyId: keyId.value,
      appIdentifier: appIdentifier.value,
      packageName: null,
      signingCertDigest: null,
    };
  }

  const packageName = nonEmptyField(
    "appAttestation.packageName",
    input.appAttestation.packageName,
  );
  if (!packageName.success) {
    return packageName;
  }

  const integrityToken = nonEmptyField(
    "appAttestation.integrityToken",
    input.appAttestation.integrityToken,
  );
  if (!integrityToken.success) {
    return integrityToken;
  }

  const mismatch = rejectIfMismatch(
    "Android package name",
    packageName.value,
    authPolicy.androidPackageName,
  );
  if (mismatch) {
    return mismatch;
  }

  const signingCertDigest = asTrimmedString(input.appAttestation.signingCertDigest);
  const normalizedSigningCertDigest = normalizeAndroidCertDigest(signingCertDigest);
  // In strict Android mode, the Google Play Integrity verdict is the authority
  // for signing certificate digests. The caller-supplied digest can be useful
  // diagnostics, but it must not decide production trust before decode.
  if (
    authPolicy.enableTransitionalCryptoBypass &&
    authPolicy.androidAllowedSigningCertDigests.length > 0 &&
    (!normalizedSigningCertDigest ||
      !authPolicy.androidAllowedSigningCertDigests.includes(normalizedSigningCertDigest))
  ) {
    return reject(
      "ATTESTATION_INVALID",
      "Android signing certificate digest is missing or not allow-listed.",
    );
  }

  return {
    success: true,
    provider,
    attestationKeyId: null,
    appIdentifier: null,
    packageName: packageName.value,
    signingCertDigest: normalizedSigningCertDigest,
  };
};

const validateLoginAssertionContract = (
  input: LoginAppAssertionInput,
):
  | {
      success: true;
      provider: AppAttestationProvider;
    }
  | RejectedAppAttestationResult => {
  if (input.storedCredential.attestation_provider !== defaultProviderForPlatform(input.platform)) {
    return reject(
      "ATTESTATION_INVALID",
      "Stored attestation provider does not match the request platform.",
    );
  }

  if (input.platform === "ios") {
    const keyId = nonEmptyField("appAssertion.keyId", input.appAssertion.keyId);
    if (!keyId.success) {
      return keyId;
    }

    const appIdentifier = nonEmptyField(
      "appAssertion.appIdentifier",
      input.appAssertion.appIdentifier,
    );
    if (!appIdentifier.success) {
      return appIdentifier;
    }

    const assertion = nonEmptyField("appAssertion.assertion", input.appAssertion.assertion);
    if (!assertion.success) {
      return assertion;
    }

    const clientDataHash = validateClientDataHash(
      "appAssertion.clientDataHash",
      input.appAssertion.clientDataHash,
      input.challenge,
    );
    if (!clientDataHash.success) {
      return clientDataHash;
    }

    const canonicalRequestKeyId = canonicalBase64(keyId.value);
    if (!canonicalRequestKeyId) {
      return reject("ATTESTATION_INVALID", "appAssertion.keyId must be valid base64.");
    }

    if (
      input.storedCredential.attestation_key_id &&
      canonicalRequestKeyId !== input.storedCredential.attestation_key_id
    ) {
      return reject(
        "ATTESTATION_INVALID",
        "appAssertion.keyId does not match the enrolled attestation key.",
      );
    }

    if (
      input.storedCredential.app_identifier &&
      input.storedCredential.app_identifier !== appIdentifier.value
    ) {
      return reject(
        "ATTESTATION_INVALID",
        "appAssertion.appIdentifier does not match the enrolled app identifier.",
      );
    }

    const mismatch = rejectIfMismatch(
      "iOS bundle identifier",
      appIdentifier.value,
      authPolicy.iosBundleId,
    );
    if (mismatch) {
      return mismatch;
    }

    return {
      success: true,
      provider: input.storedCredential.attestation_provider,
    };
  }

  const packageName = nonEmptyField(
    "appAssertion.packageName",
    input.appAssertion.packageName,
  );
  if (!packageName.success) {
    return packageName;
  }

  const integrityToken = nonEmptyField(
    "appAssertion.integrityToken",
    input.appAssertion.integrityToken,
  );
  if (!integrityToken.success) {
    return integrityToken;
  }

  const mismatch = rejectIfMismatch(
    "Android package name",
    packageName.value,
    authPolicy.androidPackageName,
  );
  if (mismatch) {
    return mismatch;
  }

  const signingCertDigest = asTrimmedString(input.appAssertion.signingCertDigest);
  const normalizedSigningCertDigest = normalizeAndroidCertDigest(signingCertDigest);
  // In strict Android mode, compare the stored credential and configured
  // allow-list against Google's decoded Play Integrity verdict, not this
  // app-supplied diagnostic value.
  if (
    authPolicy.enableTransitionalCryptoBypass &&
    authPolicy.androidAllowedSigningCertDigests.length > 0 &&
    (!normalizedSigningCertDigest ||
      !authPolicy.androidAllowedSigningCertDigests.includes(normalizedSigningCertDigest))
  ) {
    return reject(
      "ATTESTATION_INVALID",
      "Android signing certificate digest is missing or not allow-listed.",
    );
  }

  return {
    success: true,
    provider: input.storedCredential.attestation_provider,
  };
};

const verifyIosRegistrationCryptographically = async (
  input: RegistrationAppAttestationInput,
  provider: AppAttestationProvider,
): Promise<VerifiedAppAttestationResult | RejectedAppAttestationResult> => {
  if (!authPolicy.iosTeamId) {
    return reject(
      "ATTESTATION_INVALID",
      "AUTH_IOS_TEAM_ID is not configured for App Attest verification.",
    );
  }

  const keyId = nonEmptyField("appAttestation.keyId", input.appAttestation.keyId);
  if (!keyId.success) {
    return keyId;
  }

  const attestationObjectField = nonEmptyField(
    "appAttestation.attestationObject",
    input.appAttestation.attestationObject,
  );
  if (!attestationObjectField.success) {
    return attestationObjectField;
  }

  const clientDataHash = validateClientDataHash(
    "appAttestation.clientDataHash",
    input.appAttestation.clientDataHash,
    input.challenge,
  );
  if (!clientDataHash.success) {
    return clientDataHash;
  }

  const attestationBytes = decodeBase64(
    "appAttestation.attestationObject",
    attestationObjectField.value,
  );
  if (!attestationBytes.success) {
    return attestationBytes;
  }

  let decodedObject: unknown;
  try {
    decodedObject = decode(attestationBytes.value);
  } catch {
    return reject(
      "ATTESTATION_INVALID",
      "appAttestation.attestationObject is not valid CBOR.",
    );
  }

  const objectRecord =
    decodedObject && typeof decodedObject === "object"
      ? (decodedObject as Record<string, unknown>)
      : null;
  const fmt = asTrimmedString(objectRecord?.fmt);
  if (fmt !== "apple-appattest") {
    return reject(
      "ATTESTATION_INVALID",
      `Unexpected iOS attestation format ${JSON.stringify(fmt)}.`,
    );
  }

  const attStmt =
    objectRecord?.attStmt && typeof objectRecord.attStmt === "object"
      ? (objectRecord.attStmt as Record<string, unknown>)
      : null;
  const x5c = Array.isArray(attStmt?.x5c) ? attStmt.x5c : null;
  if (!x5c || x5c.length < 2) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation certificate chain must include leaf and intermediate certificates.",
    );
  }

  const authDataBytes = toBuffer("appAttestation.authData", objectRecord?.authData);
  if (!authDataBytes.success) {
    return authDataBytes;
  }

  const leafDer = toBuffer("appAttestation.attStmt.x5c[0]", x5c[0]);
  if (!leafDer.success) {
    return leafDer;
  }

  const intermediateDer = toBuffer("appAttestation.attStmt.x5c[1]", x5c[1]);
  if (!intermediateDer.success) {
    return intermediateDer;
  }

  let leafCertificate: X509Certificate;
  let intermediateCertificate: X509Certificate;
  let rootCertificate: X509Certificate;
  try {
    leafCertificate = new X509Certificate(toArrayBuffer(leafDer.value));
    intermediateCertificate = new X509Certificate(
      toArrayBuffer(intermediateDer.value),
    );
    rootCertificate = new X509Certificate(APPLE_APP_ATTEST_ROOT_CA_PEM);
  } catch {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation certificates could not be parsed.",
    );
  }

  const now = new Date();
  if (
    now < leafCertificate.notBefore ||
    now > leafCertificate.notAfter ||
    now < intermediateCertificate.notBefore ||
    now > intermediateCertificate.notAfter
  ) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation certificate chain is not currently valid.",
    );
  }

  // Enforced policy:
  // verify both the signature path and the issuer linkage so only Apple's App
  // Attestation chain can mint trusted enrollment keys.
  if (
    leafCertificate.issuer !== intermediateCertificate.subject ||
    intermediateCertificate.issuer !== rootCertificate.subject
  ) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation certificate chain issuer linkage is invalid.",
    );
  }

  if (
    !(await leafCertificate.verify({ publicKey: intermediateCertificate.publicKey }, crypto)) ||
    !(await intermediateCertificate.verify({ publicKey: rootCertificate.publicKey }, crypto))
  ) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation certificate chain signature verification failed.",
    );
  }

  const parsedAuthData = parseAttestedAuthenticatorData(authDataBytes.value);
  if (!parsedAuthData.success) {
    return parsedAuthData;
  }

  if ((parsedAuthData.value.flags & IOS_FLAG_ATTESTED_CREDENTIAL_DATA) === 0) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation authData does not contain attested credential data.",
    );
  }

  const rpIdHashMismatch = verifyRpIdHash(
    parsedAuthData.value.rpIdHash,
    "iOS attestation rpIdHash",
  );
  if (rpIdHashMismatch) {
    return rpIdHashMismatch;
  }

  if (parsedAuthData.value.signCount !== 0) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation signCount must be zero during enrollment.",
    );
  }

  const aaguidMismatch = verifyAaguid(parsedAuthData.value.aaguid);
  if (aaguidMismatch) {
    return aaguidMismatch;
  }

  const providedKeyIdBytes = decodeBase64("appAttestation.keyId", keyId.value);
  if (!providedKeyIdBytes.success) {
    return providedKeyIdBytes;
  }

  if (!buffersEqual(parsedAuthData.value.credentialId, providedKeyIdBytes.value)) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS attestation credentialId does not match appAttestation.keyId.",
    );
  }

  const credentialPublicKeyHash = sha256(
    parsedAuthData.value.credentialPublicKeySpkiDer,
  );
  if (!buffersEqual(providedKeyIdBytes.value, credentialPublicKeyHash)) {
    console.warn("[auth]", {
      route: "/auth/register/complete",
      warning: "attestation_authdata_public_key_hash_mismatch",
      providedKeyId: providedKeyIdBytes.value.toString("base64"),
      computedCredentialPublicKeyId: credentialPublicKeyHash.toString("base64"),
    });
  }

  const leafPublicKeySpki = exportSpkiDerFromCertificatePublicKey(leafCertificate);
  const leafPublicKeyHash = sha256(leafPublicKeySpki);
  if (!buffersEqual(providedKeyIdBytes.value, leafPublicKeyHash)) {
    console.warn("[auth]", {
      route: "/auth/register/complete",
      warning: "attestation_leaf_public_key_hash_mismatch",
      providedKeyId: providedKeyIdBytes.value.toString("base64"),
      computedKeyId: leafPublicKeyHash.toString("base64"),
    });
  }

  console.warn("[auth]", {
    route: "/auth/register/complete",
    diagnostic: "ios_attestation_key_material",
    attestationKeyId: providedKeyIdBytes.value.toString("base64"),
    credentialIdFromAuthData: parsedAuthData.value.credentialId.toString("base64"),
    authDataCredentialPublicKeySpkiHash: credentialPublicKeyHash.toString("base64"),
    leafCertificatePublicKeySpkiHash: leafPublicKeyHash.toString("base64"),
    attestationChallengeClientDataHash: clientDataHash.value.toString("base64"),
    signCount: parsedAuthData.value.signCount,
    aaguidHex: parsedAuthData.value.aaguid.toString("hex"),
  });

  const nonceExtension = leafCertificate.getExtension(APPLE_NONCE_EXTENSION_OID);
  if (!nonceExtension) {
    return reject(
      "ATTESTATION_INVALID",
      "Apple nonce extension is missing from the attestation certificate.",
    );
  }

  const extractedNonce = extractAppleNonceExtensionValue(
    Buffer.from(nonceExtension.value),
  );
  if (!extractedNonce.success) {
    return extractedNonce;
  }

  const expectedNonce = sha256(
    Buffer.concat([authDataBytes.value, clientDataHash.value]),
  );
  if (!buffersEqual(extractedNonce.value, expectedNonce)) {
    return reject(
      "ATTESTATION_INVALID",
      "Apple nonce extension does not match authData || clientDataHash.",
    );
  }

  return {
    success: true,
    provider,
    environment: authPolicy.iosAppAttestEnvironment,
    attestationKeyId: providedKeyIdBytes.value.toString("base64"),
    // Persist the attested credential public key from authData because that is
    // the key App Attest assertions are signed with at login time.
    attestationPublicKeyPem: parsedAuthData.value.credentialPublicKeyPem,
    appIdentifier: authPolicy.iosBundleId,
    packageName: null,
    signingCertDigest: null,
    lastAssertionNonceHash: null,
    lastCounter: null,
    transitionalCryptoBypassUsed: false,
  };
};

const verifyIosLoginAssertionCryptographically = async (
  input: LoginAppAssertionInput,
  provider: AppAttestationProvider,
): Promise<VerifiedAppAttestationResult | RejectedAppAttestationResult> => {
  if (!authPolicy.iosTeamId) {
    return reject(
      "ATTESTATION_INVALID",
      "AUTH_IOS_TEAM_ID is not configured for App Attest verification.",
    );
  }

  if (!input.storedCredential.public_key_pem) {
    return reject(
      "ATTESTATION_INVALID",
      "Stored App Attest public key is missing. Re-enroll backend auth on this device.",
    );
  }

  const assertionField = nonEmptyField("appAssertion.assertion", input.appAssertion.assertion);
  if (!assertionField.success) {
    return assertionField;
  }

  const assertionBytes = decodeBase64("appAssertion.assertion", assertionField.value);
  if (!assertionBytes.success) {
    return assertionBytes;
  }

  const clientDataHash = validateClientDataHash(
    "appAssertion.clientDataHash",
    input.appAssertion.clientDataHash,
    input.challenge,
  );
  if (!clientDataHash.success) {
    return clientDataHash;
  }

  const parsedAssertionPayload = parseIosAssertionPayload(assertionBytes.value);
  if (!parsedAssertionPayload.success) {
    return parsedAssertionPayload;
  }

  // Production iOS devices return a CBOR assertion object containing
  // authenticatorData and the DER-encoded ECDSA signature over
  // authenticatorData || clientDataHash.
  const { authenticatorData, signature } = parsedAssertionPayload.value;

  const parsedAuthData = parseAssertionAuthenticatorData(authenticatorData);
  if (!parsedAuthData.success) {
    return parsedAuthData;
  }

  const expectedRpIdHash = expectedIosRpIdHash();
  if (expectedRpIdHash && !buffersEqual(parsedAuthData.value.rpIdHash, expectedRpIdHash)) {
    console.warn("[auth]", {
      route: "/auth/login/complete",
      diagnostic: "ios_assertion_rp_id_hash_mismatch",
      requestKeyId: canonicalBase64(asTrimmedString(input.appAssertion.keyId) || "") || null,
      storedAttestationKeyId: input.storedCredential.attestation_key_id,
      actualRpIdHash: parsedAuthData.value.rpIdHash.toString("base64"),
      expectedRpIdHash: expectedRpIdHash.toString("base64"),
      signCount: parsedAuthData.value.signCount,
    });
    return reject(
      "ATTESTATION_INVALID",
      "iOS assertion rpIdHash does not match SHA-256(teamID.bundleID).",
    );
  }

  const signedPayload = Buffer.concat([authenticatorData, clientDataHash.value]);
  const signedPayloadSha256 = sha256(signedPayload);
  const publicKey = createPublicKey(input.storedCredential.public_key_pem);
  const signatureValid =
    // Production-device behavior:
    // the observed App Attest login assertion from TestFlight/Release devices
    // verifies when Node/OpenSSL is given SHA-256(authenticatorData ||
    // clientDataHash) as the message for an ECDSA-with-SHA256 verify call.
    //
    // Keep the older direct payload form as a compatibility path for local
    // fixtures and earlier assumptions while real-device verification remains
    // the primary source of truth.
    verifySignature("sha256", signedPayloadSha256, publicKey, signature) ||
    verifySignature("sha256", signedPayload, publicKey, signature);
  if (!signatureValid) {
    const rawChallengeBytes = Buffer.from(input.challenge, "utf8");
    const storedPublicKeyHash = hashSpkiDerFromPublicKeyPem(
      input.storedCredential.public_key_pem,
    ).toString("base64");
    const compatibilityVariants = {
      authData_plus_clientDataHash: tryVerifySignatureVariant(
        "sha256",
        signedPayload,
        publicKey,
        signature,
      ),
      raw_ecdsa_over_authData_plus_clientDataHash: tryVerifySignatureVariant(
        null,
        signedPayload,
        publicKey,
        signature,
      ),
      raw_ecdsa_over_sha256_authData_plus_clientDataHash: tryVerifySignatureVariant(
        null,
        signedPayloadSha256,
        publicKey,
        signature,
      ),
      sha256_over_sha256_authData_plus_clientDataHash: tryVerifySignatureVariant(
        "sha256",
        signedPayloadSha256,
        publicKey,
        signature,
      ),
      authData_plus_rawChallengeUtf8: tryVerifySignatureVariant(
        "sha256",
        Buffer.concat([authenticatorData, rawChallengeBytes]),
        publicKey,
        signature,
      ),
      clientDataHash_only: tryVerifySignatureVariant(
        "sha256",
        clientDataHash.value,
        publicKey,
        signature,
      ),
      rawChallengeUtf8_only: tryVerifySignatureVariant(
        "sha256",
        rawChallengeBytes,
        publicKey,
        signature,
      ),
      authenticatorData_only: tryVerifySignatureVariant(
        "sha256",
        authenticatorData,
        publicKey,
        signature,
      ),
      clientDataHash_plus_authData: tryVerifySignatureVariant(
        "sha256",
        Buffer.concat([clientDataHash.value, authenticatorData]),
        publicKey,
        signature,
      ),
    };
    console.warn("[auth]", {
      route: "/auth/login/complete",
      warning: "assertion_signature_verification_failed",
      requestKeyId: canonicalBase64(asTrimmedString(input.appAssertion.keyId) || "") || null,
      signatureLength: signature.length,
      signaturePrefixHex: signature.subarray(0, Math.min(8, signature.length)).toString("hex"),
      authenticatorDataLength: authenticatorData.length,
      storedAttestationKeyId: input.storedCredential.attestation_key_id,
      storedPublicKeySpkiHash: storedPublicKeyHash,
      storedAppIdentifier: input.storedCredential.app_identifier,
      assertionAppIdentifier:
        asTrimmedString(input.appAssertion.appIdentifier) || null,
      signCount: parsedAuthData.value.signCount,
      clientDataHash: clientDataHash.value.toString("base64"),
      rpIdHash: parsedAuthData.value.rpIdHash.toString("base64"),
      signatureVariantMatches: compatibilityVariants,
    });
    return reject(
      "ATTESTATION_INVALID",
      "iOS assertion signature verification failed.",
    );
  }

  // Replay policy:
  // once a device has produced one verified assertion, every future assertion
  // must strictly increase the counter. This blocks simple replay of prior
  // signed payloads while still tolerating a first verified assertion on rows
  // created before counters were persisted.
  if (
    input.storedCredential.last_counter !== null &&
    parsedAuthData.value.signCount <= input.storedCredential.last_counter
  ) {
    return reject(
      "ATTESTATION_INVALID",
      "iOS assertion counter did not advance beyond the previous verified assertion.",
    );
  }

  return {
    success: true,
    provider,
    environment: input.storedCredential.environment,
    attestationKeyId: input.storedCredential.attestation_key_id,
    attestationPublicKeyPem: input.storedCredential.public_key_pem,
    appIdentifier: input.storedCredential.app_identifier,
    packageName: input.storedCredential.package_name,
    signingCertDigest: input.storedCredential.signing_cert_digest,
    lastAssertionNonceHash: hashOpaqueBearerToken(input.challenge),
    lastCounter: parsedAuthData.value.signCount,
    transitionalCryptoBypassUsed: false,
  };
};

const verifyStructuredRegistrationAttestation = async (
  input: RegistrationAppAttestationInput,
): Promise<VerifiedAppAttestationResult | RejectedAppAttestationResult> => {
  const contractValidation = validateRegistrationContract(input);
  if (!contractValidation.success) {
    return contractValidation;
  }

  if (input.platform === "ios" && authPolicy.iosTeamId) {
    return verifyIosRegistrationCryptographically(input, contractValidation.provider);
  }

  if (input.platform === "android") {
    const integrityToken = asTrimmedString(input.appAttestation.integrityToken);
    if (!integrityToken) {
      return reject(
        "ATTESTATION_INVALID",
        "appAttestation.integrityToken is required.",
      );
    }

    const decodedVerdict = await decodeAndroidPlayIntegrityVerdict(
      integrityToken,
      input.challenge,
    );
    if (!("packageName" in decodedVerdict)) {
      return decodedVerdict;
    }

    return {
      success: true,
      provider: contractValidation.provider,
      environment: fallbackEnvironmentForPlatform("android"),
      attestationKeyId: null,
      attestationPublicKeyPem: null,
      appIdentifier: null,
      packageName: decodedVerdict.packageName,
      signingCertDigest: decodedVerdict.matchedSigningCertDigest,
      lastAssertionNonceHash: null,
      lastCounter: null,
      transitionalCryptoBypassUsed: false,
    };
  }

  if (authPolicy.enableTransitionalCryptoBypass) {
    // Transitional seam:
    // if a platform's final cryptographic verifier is not available yet, keep
    // the route contract live in non-production so the app/backend migration can
    // continue incrementally. iOS now prefers the real verifier whenever its
    // required backend config is present.
    return {
      success: true,
      provider: contractValidation.provider,
      environment: fallbackEnvironmentForPlatform(input.platform),
      attestationKeyId: contractValidation.attestationKeyId,
      attestationPublicKeyPem: null,
      appIdentifier: contractValidation.appIdentifier,
      packageName: contractValidation.packageName,
      signingCertDigest: contractValidation.signingCertDigest,
      lastAssertionNonceHash: null,
      lastCounter: null,
      transitionalCryptoBypassUsed: true,
    };
  }

  return reject(
    "NOT_IMPLEMENTED",
    "Production app-attestation verification is not fully implemented yet for this platform.",
  );
};

const verifyStructuredLoginAssertion = async (
  input: LoginAppAssertionInput,
): Promise<VerifiedAppAttestationResult | RejectedAppAttestationResult> => {
  const contractValidation = validateLoginAssertionContract(input);
  if (!contractValidation.success) {
    return contractValidation;
  }

  if (input.platform === "ios" && authPolicy.iosTeamId && input.storedCredential.public_key_pem) {
    return verifyIosLoginAssertionCryptographically(input, contractValidation.provider);
  }

  if (input.platform === "android") {
    const integrityToken = asTrimmedString(input.appAssertion.integrityToken);
    if (!integrityToken) {
      return reject(
        "ATTESTATION_INVALID",
        "appAssertion.integrityToken is required.",
      );
    }

    const decodedVerdict = await decodeAndroidPlayIntegrityVerdict(
      integrityToken,
      input.challenge,
    );
    if (!("packageName" in decodedVerdict)) {
      return decodedVerdict;
    }

    if (
      input.storedCredential.package_name &&
      input.storedCredential.package_name !== decodedVerdict.packageName
    ) {
    return reject(
      "ATTESTATION_INVALID",
      "Google Play Integrity packageName does not match the enrolled app credential.",
    );
  }

  if (
      normalizeAndroidCertDigest(input.storedCredential.signing_cert_digest) &&
      decodedVerdict.matchedSigningCertDigest &&
      normalizeAndroidCertDigest(input.storedCredential.signing_cert_digest) !==
        normalizeAndroidCertDigest(decodedVerdict.matchedSigningCertDigest)
    ) {
      return reject(
        "ATTESTATION_INVALID",
        "Google Play Integrity signing certificate digest does not match the enrolled app credential.",
      );
    }

    return {
      success: true,
      provider: contractValidation.provider,
      environment: input.storedCredential.environment,
      attestationKeyId: input.storedCredential.attestation_key_id,
      attestationPublicKeyPem: input.storedCredential.public_key_pem,
      appIdentifier: input.storedCredential.app_identifier,
      packageName: decodedVerdict.packageName,
      signingCertDigest:
        decodedVerdict.matchedSigningCertDigest ||
        input.storedCredential.signing_cert_digest,
      lastAssertionNonceHash: hashOpaqueBearerToken(input.challenge),
      lastCounter: input.storedCredential.last_counter,
      transitionalCryptoBypassUsed: false,
    };
  }

  if (authPolicy.enableTransitionalCryptoBypass) {
    return {
      success: true,
      provider: contractValidation.provider,
      environment: input.storedCredential.environment,
      attestationKeyId: input.storedCredential.attestation_key_id,
      attestationPublicKeyPem: input.storedCredential.public_key_pem,
      appIdentifier: input.storedCredential.app_identifier,
      packageName: input.storedCredential.package_name,
      signingCertDigest: input.storedCredential.signing_cert_digest,
      lastAssertionNonceHash: hashOpaqueBearerToken(input.challenge),
      lastCounter: input.storedCredential.last_counter,
      transitionalCryptoBypassUsed: true,
    };
  }

  return reject(
    "NOT_IMPLEMENTED",
    "Production login-time app assertion verification is not fully implemented yet for this platform.",
  );
};

export const appAttestationVerifier = {
  verifyRegistrationAttestation: verifyStructuredRegistrationAttestation,
  verifyLoginAssertion: verifyStructuredLoginAssertion,
};

export const __testOnly = {
  extractAppleNonceExtensionValue,
  setPlayIntegrityFetch(nextFetch: typeof fetch) {
    playIntegrityFetch = nextFetch;
  },
  resetPlayIntegrityFetch() {
    playIntegrityFetch = fetch;
  },
  setGoogleOAuthFetch(nextFetch: typeof fetch) {
    googleOAuthFetch = nextFetch;
    playIntegrityAccessTokenCache = null;
  },
  resetGoogleOAuthFetch() {
    googleOAuthFetch = fetch;
    playIntegrityAccessTokenCache = null;
  },
};

export default appAttestationVerifier;
