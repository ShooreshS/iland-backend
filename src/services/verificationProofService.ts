import type {
  VerificationProofRequestDto,
  VerificationProofResultDto,
} from "../types/contracts";

export const VERIFICATION_PROOF_STATUS = "preprover_accepted" as const;
export const VERIFICATION_PROOF_TTL_MS = 10 * 60 * 1000;
export const CIVIC_VERIFICATION_METHOD_VERSION =
  "civicos-mobile-verification-v1" as const;

const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

const normalizeHex64 = (value: string | null | undefined): string | null => {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return HEX_64_PATTERN.test(normalized) ? normalized : null;
};

const isObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const hasProofMaterial = (proof: unknown): boolean => {
  if (typeof proof === "string") {
    return proof.trim().length > 0;
  }

  if (!isObject(proof)) {
    return false;
  }

  const status = typeof proof.status === "string" ? proof.status.trim() : "";
  const version = typeof proof.version === "string" ? proof.version.trim() : "";
  return Boolean(status && version);
};

export const verificationProofService = {
  verifyProof(input: VerificationProofRequestDto): VerificationProofResultDto {
    const credentialSchemaHash = normalizeHex64(input.credentialSchemaHash);
    const credentialCommitment = normalizeHex64(
      input.publicInputs.credentialCommitment,
    );
    const verificationMethodVersion =
      input.publicInputs.verificationMethodVersion.trim();

    if (
      !credentialSchemaHash ||
      !credentialCommitment ||
      !hasProofMaterial(input.proof)
    ) {
      return {
        verified: false,
        errorCode: "INVALID_PROOF",
        message: "Verification proof request does not contain valid public proof material.",
      };
    }

    if (verificationMethodVersion !== CIVIC_VERIFICATION_METHOD_VERSION) {
      return {
        verified: false,
        errorCode: "UNSUPPORTED_VERSION",
        message: "Verification proof uses an unsupported verification method version.",
      };
    }

    return {
      verified: true,
      credentialCommitment,
      credentialSchemaHash,
      verificationMethodVersion,
      proofVerificationStatus: VERIFICATION_PROOF_STATUS,
      expiresAt: new Date(Date.now() + VERIFICATION_PROOF_TTL_MS).toISOString(),
    };
  },
};

export default verificationProofService;
