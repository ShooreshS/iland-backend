import { createHash } from "node:crypto";

import identityProfileRepository from "../repositories/identityProfileRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import type {
  CredentialIssuanceMaterialDto,
  CredentialIssuanceResultDto,
} from "../types/contracts";
import type {
  IdentityProfileRow,
  VerifiedIdentityRow,
} from "../types/db";
import {
  CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME,
  CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
  credentialRegistryService,
  normalizeCredentialRegistryHex64,
} from "./credentialRegistryService";
import {
  canonicalizeJson,
  normalizeCountryCode,
} from "./pollPolicyService";

export const CIVIC_CREDENTIAL_CLAIMS_VERSION =
  "civicos-credential-claims-v1" as const;
export const CIVIC_CREDENTIAL_ISSUER_ID =
  "did:civicos:credential-registry:v1" as const;

const CIVIC_CREDENTIAL_CLAIMS_HASH_DOMAIN =
  "org.civicos.zkp:credential-claims:v1" as const;

export type CivicCredentialClaims = {
  version: typeof CIVIC_CREDENTIAL_CLAIMS_VERSION;
  subject: {
    identityAnchorScheme: "poseidon-canonical-identity-key-v1";
    normalizationVersion: number;
    verificationMethod: string;
    verifiedAt: string;
  };
  document: {
    verified: boolean;
    verifiedBy: "passport" | "national_id" | "verified_identity";
    countryCode: string | null;
    issuingCountryCode: string | null;
  };
  personBinding: {
    livenessPassed: boolean;
    faceMatchedDocument: boolean;
    faceVerifiedAt: string | null;
  };
  residence: {
    countryCode: string | null;
    areaId: string | null;
    source: string | null;
  };
};

type VerifiedIdentityRepositoryPort = Pick<
  typeof verifiedIdentityRepository,
  "getByUserId"
>;

type IdentityProfileRepositoryPort = Pick<
  typeof identityProfileRepository,
  "getByUserId"
>;

type CredentialRegistryServicePort = Pick<
  typeof credentialRegistryService,
  "deriveIdentityKeyHash" | "issueCredentialRegistryEntry"
>;

type IssueCredentialForViewerInput = Readonly<{
  viewerUserId: string;
  credentialSchemaHash: string;
  credentialCommitment?: string | null;
}>;

const normalizeOptionalString = (value: unknown): string | null => {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized.length > 0 ? normalized : null;
};

const resolveVerifiedBy = (
  identityProfile: IdentityProfileRow,
): CivicCredentialClaims["document"]["verifiedBy"] => {
  if (identityProfile.passport_verified_at) {
    return "passport";
  }

  if (identityProfile.national_id_verified_at) {
    return "national_id";
  }

  return "verified_identity";
};

export const buildCivicCredentialClaims = (input: {
  verifiedIdentity: VerifiedIdentityRow;
  identityProfile: IdentityProfileRow;
}): CivicCredentialClaims => {
  const { verifiedIdentity, identityProfile } = input;
  const documentVerified = Boolean(
    identityProfile.passport_verified_at ||
      identityProfile.national_id_verified_at ||
      verifiedIdentity.verified_at,
  );
  const livenessPassed = Boolean(
    identityProfile.face_verified_at || identityProfile.face_scan_completed,
  );

  return {
    version: CIVIC_CREDENTIAL_CLAIMS_VERSION,
    subject: {
      identityAnchorScheme: "poseidon-canonical-identity-key-v1",
      normalizationVersion: verifiedIdentity.normalization_version,
      verificationMethod: verifiedIdentity.verification_method,
      verifiedAt: verifiedIdentity.verified_at,
    },
    document: {
      verified: documentVerified,
      verifiedBy: resolveVerifiedBy(identityProfile),
      countryCode: normalizeCountryCode(identityProfile.document_country_code),
      issuingCountryCode: normalizeCountryCode(identityProfile.issuing_country_code),
    },
    personBinding: {
      livenessPassed,
      faceMatchedDocument: Boolean(identityProfile.face_bound_to_identity),
      faceVerifiedAt: identityProfile.face_verified_at,
    },
    residence: {
      countryCode: normalizeCountryCode(identityProfile.home_country_code),
      areaId: normalizeOptionalString(identityProfile.home_area_id),
      source: normalizeOptionalString(identityProfile.home_location_source),
    },
  };
};

export const hashCivicCredentialClaims = (
  claims: CivicCredentialClaims,
): string =>
  createHash("sha256")
    .update(CIVIC_CREDENTIAL_CLAIMS_HASH_DOMAIN, "utf8")
    .update("\0", "utf8")
    .update(canonicalizeJson(claims), "utf8")
    .digest("hex");

const claimsAreIssuable = (claims: CivicCredentialClaims): boolean =>
  claims.document.verified &&
  claims.personBinding.livenessPassed &&
  claims.personBinding.faceMatchedDocument;

const failure = (
  errorCode: Extract<CredentialIssuanceResultDto, { success: false }>["errorCode"],
  message: string,
): CredentialIssuanceResultDto => ({
  success: false,
  errorCode,
  message,
});

const mapMaterial = (input: {
  identityKeyHash: string;
  credentialSchemaHash: string;
  claimsHash: string;
}): CredentialIssuanceMaterialDto => ({
  identityKeyHash: input.identityKeyHash,
  credentialSchemaHash: input.credentialSchemaHash,
  claimsHash: input.claimsHash,
  credentialIssuerId: CIVIC_CREDENTIAL_ISSUER_ID,
  commitmentScheme: CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME,
  merkleDepth: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
});

export const createCredentialIssuanceService = (
  overrides: Partial<{
    verifiedIdentityRepository: VerifiedIdentityRepositoryPort;
    identityProfileRepository: IdentityProfileRepositoryPort;
    credentialRegistryService: CredentialRegistryServicePort;
  }> = {},
) => {
  const verifiedIdentityRepo =
    overrides.verifiedIdentityRepository ?? verifiedIdentityRepository;
  const identityProfileRepo =
    overrides.identityProfileRepository ?? identityProfileRepository;
  const registryService =
    overrides.credentialRegistryService ?? credentialRegistryService;

  return {
    async issueCredentialForViewer(
      input: IssueCredentialForViewerInput,
    ): Promise<CredentialIssuanceResultDto> {
      const viewerUserId = normalizeOptionalString(input.viewerUserId);
      if (!viewerUserId) {
        return failure("INVALID_INPUT", "Viewer user id is required.");
      }

      let credentialSchemaHash: string;
      try {
        credentialSchemaHash = normalizeCredentialRegistryHex64(
          "credentialSchemaHash",
          input.credentialSchemaHash,
        );
      } catch {
        return failure(
          "INVALID_INPUT",
          "Credential schema hash must be a 32-byte hex value.",
        );
      }

      const [verifiedIdentity, identityProfile] = await Promise.all([
        verifiedIdentityRepo.getByUserId(viewerUserId),
        identityProfileRepo.getByUserId(viewerUserId),
      ]);

      if (!verifiedIdentity) {
        return failure(
          "VERIFIED_IDENTITY_REQUIRED",
          "A linked verified identity is required before issuing a ZKP credential.",
        );
      }

      if (!identityProfile) {
        return failure(
          "IDENTITY_PROFILE_REQUIRED",
          "A backend identity profile is required before issuing a ZKP credential.",
        );
      }

      const claims = buildCivicCredentialClaims({
        verifiedIdentity,
        identityProfile,
      });
      if (!claimsAreIssuable(claims)) {
        return failure(
          "IDENTITY_PROFILE_REQUIRED",
          "The identity profile must have document, liveness, and face binding checks before issuing a ZKP credential.",
        );
      }

      const identityKeyHash = await registryService.deriveIdentityKeyHash(
        verifiedIdentity.canonical_identity_key,
      );
      const claimsHash = hashCivicCredentialClaims(claims);
      const material = mapMaterial({
        identityKeyHash,
        credentialSchemaHash,
        claimsHash,
      });

      if (!input.credentialCommitment) {
        return {
          success: true,
          status: "material",
          material,
        };
      }

      let credentialCommitment: string;
      try {
        credentialCommitment = normalizeCredentialRegistryHex64(
          "credentialCommitment",
          input.credentialCommitment,
        );
      } catch {
        return failure(
          "INVALID_INPUT",
          "Credential commitment must be a 32-byte hex value.",
        );
      }

      try {
        const issued = await registryService.issueCredentialRegistryEntry({
          verifiedIdentity,
          credentialCommitment,
          credentialSchemaHash,
          claimsHash,
          credentialIssuerId: CIVIC_CREDENTIAL_ISSUER_ID,
          commitmentScheme: CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME,
          merkleDepth: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
        });

        return {
          success: true,
          status: issued.status,
          credential: {
            ...material,
            credentialCommitment: issued.registryEntry.credential_commitment,
            credentialRoot: issued.credentialRoot.root,
            leafIndex: issued.registryEntry.leaf_index,
            leafCount: issued.credentialRoot.leaf_count,
            credentialRootSiblings: issued.merklePath.siblings,
            credentialRootPathIndices: issued.merklePath.pathIndices,
            credentialRootCreatedAt: issued.credentialRoot.created_at,
          },
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes("different credential registry entry")) {
          return failure(
            "CREDENTIAL_CONFLICT",
            "This verified identity already has different ZKP credential material.",
          );
        }
        throw error;
      }
    },
  };
};

export const credentialIssuanceService = createCredentialIssuanceService();

export default credentialIssuanceService;
