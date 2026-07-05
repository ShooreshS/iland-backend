import { describe, expect, it } from "bun:test";

import {
  createGetVerificationProofSystemRoute,
  createGetVerificationSecurityPolicyRoute,
  createPostVerificationProofRoute,
} from "./verification";
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
          proofVerificationMode: "off_chain_preprover",
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
      proofVerificationMode: "off_chain_preprover",
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

describe("GET /verification/proof-system route", () => {
  it("returns the selected Phase 11 v1 proof-system policy", async () => {
    const route = createGetVerificationProofSystemRoute();
    const request = new Request(
      "http://127.0.0.1:3001/verification/proof-system",
      {
        method: "GET",
      },
    );

    const response = await route.handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      version: "civicos-proof-system-policy-v1",
      phase: 11,
      selectedTrack: "v1",
      proofVerificationMode: "off_chain_preprover",
      onChainZkVerifierEnabled: false,
      solanaAnchoring: "audit_roots_only",
      storesProofHash: true,
      storesPublicInputs: true,
      storesPrivateWitness: false,
    });
  });
});

describe("GET /verification/security-policy route", () => {
  it("returns the selected Phase 12 security policy", async () => {
    const route = createGetVerificationSecurityPolicyRoute();
    const request = new Request(
      "http://127.0.0.1:3001/verification/security-policy",
      {
        method: "GET",
      },
    );

    const response = await route.handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      version: "civicos-zkp-security-policy-v1",
      phase: 12,
      backendSigner: {
        role: "root_publisher_key",
        privateKeyMaterialAcceptedByBackend: false,
        keypairFilesAllowedInRepository: false,
        transactionsEnabled: false,
      },
      programUpgradeAuthority: {
        developerWalletAllowed: false,
        backendControlsUpgradeAuthority: false,
        multisigRequired: true,
      },
      auditLog: {
        table: "backend_audit_events",
        appendRpc: "append_backend_audit_event",
        anchorTarget: "audit_log_root",
      },
    });
  });
});
