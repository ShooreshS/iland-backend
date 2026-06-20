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

const nonEmptyField = (
  label: string,
  value: unknown,
): { success: true; value: string } | RejectedAppAttestationResult => {
  const normalized = asTrimmedString(value);
  if (!normalized) {
    return {
      success: false,
      errorCode: "ATTESTATION_INVALID",
      message: `${label} is required.`,
    };
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

  return {
    success: false,
    errorCode: "ATTESTATION_INVALID",
    message: `${label} does not match the configured app identity.`,
  };
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
    return {
      success: false,
      errorCode: "ATTESTATION_INVALID",
      message: "Attestation provider does not match the request platform.",
    };
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
  if (
    authPolicy.androidAllowedSigningCertDigests.length > 0 &&
    (!signingCertDigest ||
      !authPolicy.androidAllowedSigningCertDigests.includes(signingCertDigest))
  ) {
    return {
      success: false,
      errorCode: "ATTESTATION_INVALID",
      message:
        "Android signing certificate digest is missing or not allow-listed.",
    };
  }

  return {
    success: true,
    provider,
    attestationKeyId: null,
    appIdentifier: null,
    packageName: packageName.value,
    signingCertDigest,
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
    return {
      success: false,
      errorCode: "ATTESTATION_INVALID",
      message: "Stored attestation provider does not match the request platform.",
    };
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

    if (
      input.storedCredential.attestation_key_id &&
      keyId.value !== input.storedCredential.attestation_key_id
    ) {
      return {
        success: false,
        errorCode: "ATTESTATION_INVALID",
        message: "appAssertion.keyId does not match the enrolled attestation key.",
      };
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
  if (
    authPolicy.androidAllowedSigningCertDigests.length > 0 &&
    (!signingCertDigest ||
      !authPolicy.androidAllowedSigningCertDigests.includes(signingCertDigest))
  ) {
    return {
      success: false,
      errorCode: "ATTESTATION_INVALID",
      message:
        "Android signing certificate digest is missing or not allow-listed.",
    };
  }

  return {
    success: true,
    provider: input.storedCredential.attestation_provider,
  };
};

const verifyStructuredRegistrationAttestation = (
  input: RegistrationAppAttestationInput,
): VerifiedAppAttestationResult | RejectedAppAttestationResult => {
  const contractValidation = validateRegistrationContract(input);
  if (!contractValidation.success) {
    return contractValidation;
  }

  if (authPolicy.enableTransitionalCryptoBypass) {
    // Transitional seam:
    // the current mobile app does not yet send the final production attestation
    // assertion shape consistently. Non-production environments may therefore
    // accept the route contract without the final cryptographic verifier while
    // still persisting provider metadata and enforcing the auth-service flow.
    return {
      success: true,
      provider: contractValidation.provider,
      environment: resolveEnvironment(),
      attestationKeyId: contractValidation.attestationKeyId,
      appIdentifier: contractValidation.appIdentifier,
      packageName: contractValidation.packageName,
      signingCertDigest: contractValidation.signingCertDigest,
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
  const contractValidation = validateLoginAssertionContract(input);
  if (!contractValidation.success) {
    return contractValidation;
  }

  if (authPolicy.enableTransitionalCryptoBypass) {
    return {
      success: true,
      provider: contractValidation.provider,
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
