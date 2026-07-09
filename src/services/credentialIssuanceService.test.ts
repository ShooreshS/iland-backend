import { describe, expect, it } from "bun:test";

import type {
  CredentialRegistryRow,
  CredentialRootRow,
  IdentityProfileRow,
  VerifiedIdentityRow,
} from "../types/db";
import {
  CIVIC_CREDENTIAL_ISSUER_ID,
  buildCivicCredentialClaims,
  createCredentialIssuanceService,
  hashCivicCredentialClaims,
} from "./credentialIssuanceService";
import { CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH } from "./credentialRegistryConstants";

const FIXED_TIME = "2026-07-08T12:00:00.000Z";
const hex = (char: string): string => char.repeat(64);

const verifiedIdentity: VerifiedIdentityRow = {
  id: "verified-identity-1",
  user_id: "user-1",
  canonical_identity_key: hex("a"),
  normalization_version: 1,
  verification_method: "passport_nfc",
  verified_at: FIXED_TIME,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
};

const identityProfile: IdentityProfileRow = {
  id: "identity-profile-1",
  user_id: "user-1",
  passport_scan_completed: true,
  passport_nfc_completed: true,
  national_id_scan_completed: false,
  face_scan_completed: true,
  face_bound_to_identity: true,
  passport_verified_at: FIXED_TIME,
  national_id_verified_at: null,
  face_verified_at: FIXED_TIME,
  document_country_code: "se",
  issuing_country_code: "se",
  home_country_code: "se",
  home_area_id: "stockholm",
  home_approx_latitude: 59.33,
  home_approx_longitude: 18.06,
  home_location_source: "user_selected",
  home_location_updated_at: FIXED_TIME,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
};

const registryEntry = (credentialCommitment: string): CredentialRegistryRow => ({
  id: "credential-registry-1",
  verified_identity_id: verifiedIdentity.id,
  identity_key_hash: hex("b"),
  credential_commitment: credentialCommitment,
  credential_schema_hash: hex("2"),
  claims_hash: hex("c"),
  credential_issuer_id: CIVIC_CREDENTIAL_ISSUER_ID,
  commitment_scheme: "civicos-credential-commitment-v1",
  merkle_depth: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
  leaf_index: 0,
  revoked_at: null,
  revocation_reason: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
});

const credentialRoot: CredentialRootRow = {
  id: "credential-root-1",
  root: hex("d"),
  previous_root: null,
  merkle_depth: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
  leaf_count: 1,
  latest_credential_registry_id: "credential-registry-1",
  solana_tx_signature: null,
  created_at: FIXED_TIME,
};

const createService = (overrides: {
  verifiedIdentity?: VerifiedIdentityRow | null;
  identityProfile?: IdentityProfileRow | null;
  issueStatus?: "issued" | "existing";
} = {}) =>
  createCredentialIssuanceService({
    verifiedIdentityRepository: {
      getByUserId: async () =>
        overrides.verifiedIdentity === undefined
          ? verifiedIdentity
          : overrides.verifiedIdentity,
    },
    identityProfileRepository: {
      getByUserId: async () =>
        overrides.identityProfile === undefined
          ? identityProfile
          : overrides.identityProfile,
    },
    credentialRegistryService: {
      deriveIdentityKeyHash: async () => hex("b"),
      issueCredentialRegistryEntry: async (input) => ({
        status: overrides.issueStatus ?? "issued",
        registryEntry: {
          ...registryEntry(input.credentialCommitment),
          credential_schema_hash: input.credentialSchemaHash,
          claims_hash: input.claimsHash,
        },
        credentialRoot,
        merklePath: {
          root: credentialRoot.root,
          siblings: Array.from(
            { length: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH },
            () => hex("0"),
          ),
          pathIndices: Array.from(
            { length: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH },
            () => 0,
          ),
        },
      }),
    },
  });

describe("credentialIssuanceService", () => {
  it("builds stable server-authoritative credential claims hashes", () => {
    const claims = buildCivicCredentialClaims({
      verifiedIdentity,
      identityProfile,
    });
    const first = hashCivicCredentialClaims(claims);
    const second = hashCivicCredentialClaims(claims);

    expect(claims.document.countryCode).toBe("SE");
    expect(claims.personBinding.faceMatchedDocument).toBe(true);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(first).toBe(second);
  });

  it("returns credential material before the device submits its commitment", async () => {
    const result = await createService().issueCredentialForViewer({
      viewerUserId: "user-1",
      credentialSchemaHash: hex("2"),
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.status).toBe("material");
      if (result.status === "material") {
        expect(result.material).toMatchObject({
          identityKeyHash: hex("b"),
          credentialSchemaHash: hex("2"),
          credentialIssuerId: CIVIC_CREDENTIAL_ISSUER_ID,
          commitmentScheme: "civicos-credential-commitment-v1",
          merkleDepth: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
        });
        expect(result.material.claimsHash).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it("issues registry path material for a submitted commitment", async () => {
    const result = await createService({ issueStatus: "existing" })
      .issueCredentialForViewer({
        viewerUserId: "user-1",
        credentialSchemaHash: hex("2"),
        credentialCommitment: hex("1"),
      });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.status).toBe("existing");
      if (result.status !== "material") {
        expect(result.credential.credentialCommitment).toBe(hex("1"));
        expect(result.credential.credentialRoot).toBe(hex("d"));
        expect(result.credential.credentialRootSiblings).toHaveLength(
          CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
        );
        expect(result.credential.credentialRootPathIndices).toHaveLength(
          CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
        );
      }
    }
  });

  it("fails closed without a linked verified identity", async () => {
    const result = await createService({ verifiedIdentity: null })
      .issueCredentialForViewer({
        viewerUserId: "user-1",
        credentialSchemaHash: hex("2"),
      });

    expect(result).toMatchObject({
      success: false,
      errorCode: "VERIFIED_IDENTITY_REQUIRED",
    });
  });
});
