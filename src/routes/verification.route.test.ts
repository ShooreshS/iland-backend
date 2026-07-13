import { describe, expect, it } from "bun:test";

import {
  createGetVerificationCredentialRootsRoute,
  createGetVerificationProofSystemRoute,
  createGetVerificationSecurityPolicyRoute,
  createPostVerificationCredentialRoute,
  createPostVerificationProofRoute,
} from "./verification";
import type {
  CredentialIssuanceResultDto,
  VerificationProofResultDto,
} from "../types/contracts";

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

const invokeCredentialRoute = async (
  body: unknown,
  serviceResult?: CredentialIssuanceResultDto,
): Promise<Response> => {
  const route = createPostVerificationCredentialRoute({
    requireViewerFn: async () =>
      ({
        ok: true,
        viewer: {
          userId: "user-1",
          user: { id: "user-1", account_status: "active" },
        },
      }) as any,
    credentialIssuanceServiceLike: {
      issueCredentialForViewer: async (input) =>
        serviceResult || {
          success: true,
          status: input.credentialCommitment ? "issued" : "material",
          ...(input.credentialCommitment
            ? {
                credential: {
                  identityKeyHash: "1".repeat(64),
                  credentialSchemaHash: input.credentialSchemaHash,
                  claimsHash: "2".repeat(64),
                  credentialIssuerId: "did:civicos:credential-registry:v1",
                  commitmentScheme: "civicos-credential-commitment-v1",
                  merkleDepth: 32,
                  credentialCommitment: input.credentialCommitment,
                  credentialRoot: "3".repeat(64),
                  leafIndex: 0,
                  leafCount: 1,
                  credentialRootSiblings: Array.from({ length: 32 }, () =>
                    "0".repeat(64),
                  ),
                  credentialRootPathIndices: Array.from({ length: 32 }, () => 0),
                  credentialRootCreatedAt: "2026-07-08T12:00:00.000Z",
                },
              }
            : {
                material: {
                  identityKeyHash: "1".repeat(64),
                  credentialSchemaHash: input.credentialSchemaHash,
                  claimsHash: "2".repeat(64),
                  credentialIssuerId: "did:civicos:credential-registry:v1",
                  commitmentScheme: "civicos-credential-commitment-v1",
                  merkleDepth: 32,
                },
              }),
        } as CredentialIssuanceResultDto,
    },
  });
  const request = new Request("http://127.0.0.1:3001/verification/credential", {
    method: "POST",
    body: JSON.stringify(body),
  });

  return route.handler({
    request,
    url: new URL(request.url),
    params: {},
  });
};

describe("POST /verification/credential route", () => {
  it("returns server credential material before commitment issuance", async () => {
    const response = await invokeCredentialRoute({
      credentialSchemaHash: "a".repeat(64),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      success: true,
      status: "material",
      material: {
        credentialSchemaHash: "a".repeat(64),
        identityKeyHash: "1".repeat(64),
        claimsHash: "2".repeat(64),
      },
    });
  });

  it("returns registry path material after commitment issuance", async () => {
    const response = await invokeCredentialRoute({
      credentialSchemaHash: "a".repeat(64),
      credentialCommitment: "b".repeat(64),
    });

    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({
      success: true,
      status: "issued",
      credential: {
        credentialCommitment: "b".repeat(64),
        credentialRoot: "3".repeat(64),
        leafIndex: 0,
      },
    });
  });

  it("rejects invalid credential request bodies", async () => {
    const response = await invokeCredentialRoute({
      credentialSchemaHash: "not-a-hash",
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
    const policy = {
      version: "civicos-zkp-security-policy-v1",
      phase: 12,
      backendSigner: {
        role: "fee_payer_key",
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
    };
    const route = createGetVerificationSecurityPolicyRoute({
      zkpSecurityPolicyServiceLike: {
        getPolicy: () => policy as any,
      },
    });
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
    expect(await response.json()).toMatchObject(policy);
  });
});

describe("GET /verification/credential-roots route", () => {
  it("returns public accepted credential-root audit data", async () => {
    const route = createGetVerificationCredentialRootsRoute({
      credentialRootAuditServiceLike: {
        getCredentialRootAudit: async (input) => ({
          version: "civicos-credential-root-audit-v1",
          commitmentScheme: "civicos-credential-commitment-v1",
          merkleDepth: 32,
          identityMaterialExposed: false,
          latestRoot: {
            root: "1".repeat(64),
            previousRoot: null,
            merkleDepth: 32,
            leafCount: 1,
            createdAt: "2026-07-13T00:00:00.000Z",
            solanaTxSignature: null,
          },
          acceptedRoots:
            input?.limit === "1"
              ? [
                  {
                    root: "1".repeat(64),
                    previousRoot: null,
                    merkleDepth: 32,
                    leafCount: 1,
                    createdAt: "2026-07-13T00:00:00.000Z",
                    solanaTxSignature: null,
                  },
                ]
              : [],
          anchoring: {
            mode: "public-api-root-chain",
            solanaTxSignatureField: "solanaTxSignature",
            registryRowIdsExposed: false,
            credentialCommitmentsExposed: false,
          },
        }),
      },
    });
    const request = new Request(
      "http://127.0.0.1:3001/verification/credential-roots?limit=1",
      { method: "GET" },
    );

    const response = await route.handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      version: "civicos-credential-root-audit-v1",
      merkleDepth: 32,
      identityMaterialExposed: false,
      acceptedRoots: [
        {
          root: "1".repeat(64),
          previousRoot: null,
          leafCount: 1,
          solanaTxSignature: null,
        },
      ],
      anchoring: {
        registryRowIdsExposed: false,
        credentialCommitmentsExposed: false,
      },
    });
  });
});
