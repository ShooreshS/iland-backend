import { hashOpaqueBearerToken } from "./tokens";
import authPolicy from "./policy";
import type {
  AppAttestationProvider,
  AppAttestationEnvironment,
  AppAttestationCredentialRow,
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
  appIdentifier: string | null;
  packageName: string | null;
  signingCertDigest: string | null;
  lastAssertionNonceHash: string | null;
  transitionalCryptoBypassUsed: boolean;
};

type RejectedAppAttestationResult = {
  success: false;
  errorCode: "ATTESTATION_INVALID" | "NOT_IMPLEMENTED";
  message: string;
};

const asTrimmedString = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
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

const resolveEnvironment = (): AppAttestationEnvironment =>
  authPolicy.enableTransitionalCryptoBypass ? "development" : "production";

const verifyStructuredRegistrationAttestation = (
  input: RegistrationAppAttestationInput,
): VerifiedAppAttestationResult | RejectedAppAttestationResult => {
  if (authPolicy.enableTransitionalCryptoBypass) {
    // Transitional seam:
    // the current mobile app does not yet send the final production attestation
    // assertion shape consistently. Non-production environments may therefore
    // accept the route contract without the final cryptographic verifier while
    // still persisting provider metadata and enforcing the auth-service flow.
    return {
      success: true,
      provider: normalizeProvider(input.platform, input.appAttestation.provider),
      environment: resolveEnvironment(),
      attestationKeyId: asTrimmedString(input.appAttestation.keyId),
      appIdentifier: asTrimmedString(input.appAttestation.appIdentifier),
      packageName: asTrimmedString(input.appAttestation.packageName),
      signingCertDigest: asTrimmedString(input.appAttestation.signingCertDigest),
      lastAssertionNonceHash: null,
      transitionalCryptoBypassUsed: true,
    };
  }

  return {
    success: false,
    errorCode: "NOT_IMPLEMENTED",
    message:
      "Production app-attestation verification is not implemented yet. Full App Attest / Play Integrity cryptographic verification must be added before launch.",
  };
};

const verifyStructuredLoginAssertion = (
  input: LoginAppAssertionInput,
): VerifiedAppAttestationResult | RejectedAppAttestationResult => {
  if (authPolicy.enableTransitionalCryptoBypass) {
    return {
      success: true,
      provider: input.storedCredential.attestation_provider,
      environment: input.storedCredential.environment,
      attestationKeyId: input.storedCredential.attestation_key_id,
      appIdentifier: input.storedCredential.app_identifier,
      packageName: input.storedCredential.package_name,
      signingCertDigest: input.storedCredential.signing_cert_digest,
      lastAssertionNonceHash: hashOpaqueBearerToken(input.challenge),
      transitionalCryptoBypassUsed: true,
    };
  }

  return {
    success: false,
    errorCode: "NOT_IMPLEMENTED",
    message:
      "Production login-time app assertion verification is not implemented yet. Full App Attest assertion or Play Integrity token verification must be added before launch.",
  };
};

export const appAttestationVerifier = {
  verifyRegistrationAttestation: verifyStructuredRegistrationAttestation,
  verifyLoginAssertion: verifyStructuredLoginAssertion,
};

export default appAttestationVerifier;
