import { describe, expect, it } from "bun:test";

import { createPostVerificationProofRoute } from "./verification";
import type { VerificationProofResultDto } from "../types/contracts";

const invokeRoute = async (
  body: unknown,
  serviceResult?: VerificationProofResultDto,
): Promise<Response> => {
  const route = createPostVerificationProofRoute({
    verificationProofServiceLike: {
      verifyProof: (input) =>
        serviceResult || {
          verified: true,
          credentialCommitment: input.publicInputs.credentialCommitment,
          credentialSchemaHash: input.credentialSchemaHash,
          verificationMethodVersion:
            input.publicInputs.verificationMethodVersion,
          proofVerificationStatus: "preprover_accepted",
          expiresAt: "2026-07-05T12:10:00.000Z",
        },
    },
  });
  const request = new Request("http://127.0.0.1:3001/verification/proof", {
    method: "POST",
    body: JSON.stringify(body),
  });

  return route.handler({
    request,
    url: new URL(request.url),
    params: {},
  });
};

describe("POST /verification/proof route", () => {
  it("accepts public proof material and returns verifier result", async () => {
    const response = await invokeRoute({
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

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      verified: true,
      credentialCommitment: "2".repeat(64),
      credentialSchemaHash: "1".repeat(64),
      verificationMethodVersion: "civicos-mobile-verification-v1",
      proofVerificationStatus: "preprover_accepted",
      expiresAt: "2026-07-05T12:10:00.000Z",
    });
  });

  it("rejects invalid request bodies", async () => {
    const response = await invokeRoute({
      credentialSchemaHash: "not-a-hash",
      publicInputs: {
        credentialCommitment: "2".repeat(64),
        verificationMethodVersion: "civicos-mobile-verification-v1",
      },
    });

    expect(response.status).toBe(400);
  });
});
