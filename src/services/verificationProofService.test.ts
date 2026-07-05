import { describe, expect, it } from "bun:test";

import { verificationProofService } from "./verificationProofService";

describe("verificationProofService", () => {
  it("accepts a pre-prover verification proof with public commitments only", () => {
    const result = verificationProofService.verifyProof({
      credentialSchemaHash: "1".repeat(64),
      proof: {
        version: "civicos-proof-envelope-v1",
        status: "not_generated",
      },
      publicInputs: {
        credentialCommitment: "2".repeat(64),
        verificationMethodVersion: "civicos-mobile-verification-v1",
      },
    });

    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.credentialCommitment).toBe("2".repeat(64));
      expect(result.proofVerificationMode).toBe("off_chain_preprover");
      expect(result.proofVerificationStatus).toBe("preprover_accepted");
      expect(Date.parse(result.expiresAt)).toBeGreaterThan(Date.now());
    }
  });

  it("rejects unsupported verification method versions", () => {
    const result = verificationProofService.verifyProof({
      credentialSchemaHash: "1".repeat(64),
      proof: {
        version: "civicos-proof-envelope-v1",
        status: "not_generated",
      },
      publicInputs: {
        credentialCommitment: "2".repeat(64),
        verificationMethodVersion: "unsupported",
      },
    });

    expect(result).toEqual({
      verified: false,
      errorCode: "UNSUPPORTED_VERSION",
      message: "Verification proof uses an unsupported verification method version.",
    });
  });
});
