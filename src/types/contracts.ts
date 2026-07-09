export const VOTING_CONTRACT_VERSION = "0.0.86" as const;

export type PollStatus = "draft" | "scheduled" | "active" | "closed" | "archived";

export type PollJurisdictionType =
  | "global"
  | "real_country"
  | "real_area"
  | "land";

export type PollVotePrivacyMode =
  | "legacy_identity_linked"
  | "zk_preprover_audit"
  | "zk_secret_ballot_v1";

export type PollEligibilityRule = {
  requiresVerifiedIdentity: boolean;
  allowedDocumentCountryCodes?: string[];
  allowedHomeAreaIds?: string[];
  allowedLandIds?: string[];
  minimumAge?: number | null;
};

export type PollDto = {
  id: string;
  slug: string;
  createdByUserId: string | null;
  title: string;
  description: string | null;
  status: PollStatus;
  jurisdictionType: PollJurisdictionType;
  jurisdictionCountryCode: string | null;
  jurisdictionAreaIds: string[];
  jurisdictionLandIds: string[];
  eligibilityRule: PollEligibilityRule;
  pollPolicyHash: string | null;
  credentialSchemaHash: string | null;
  votePrivacyMode: PollVotePrivacyMode;
  optionSetHash: string | null;
  pollEncryptionKeyId: string | null;
  startsAt: string | null;
  endsAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type PollEncryptionKeyDto = {
  version: "civicos-poll-encryption-key-v1";
  pollId: string;
  pollEncryptionKeyId: string;
  status: "active" | "revoked";
  algorithm: "x25519-hkdf-sha256-aes-256-gcm-v1";
  keyAgreement: "x25519";
  kdf: "hkdf-sha256";
  cipher: "aes-256-gcm";
  publicKeyJwk: {
    kty: "OKP";
    crv: "X25519";
    x: string;
  };
  publicKeyHash: string;
  encryptedVoteVersion: "civicos-encrypted-vote-v1";
  encryptedVoteOpeningVersion: "civicos-encrypted-vote-opening-v1";
  encryptedVoteCommitmentScheme: "poseidon-encrypted-vote-opening-v1";
  custody: {
    model: string;
    threshold: boolean;
    privateKeyMaterialExposedByApi: false;
  };
  createdAt: string;
};

export type PollEncryptionKeyResultDto =
  | {
      success: true;
      key: PollEncryptionKeyDto;
    }
  | {
      success: false;
      errorCode:
        | "INVALID_INPUT"
        | "POLL_NOT_FOUND"
        | "ENCRYPTION_KEY_NOT_REQUIRED"
        | "ENCRYPTION_KEY_NOT_CONFIGURED"
        | "ENCRYPTION_KEY_CONFLICT";
      message: string;
    };

export type PollOptionDto = {
  id: string;
  pollId: string;
  label: string;
  description: string | null;
  color: string | null;
  order: number;
  isActive: boolean;
  createdAt: string;
};

export type ViewerVoteSummaryDto = {
  pollId: string;
  optionId: string;
  submittedAt: string;
};

export type PollOptionResultDto = {
  optionId: string;
  label: string;
  count: number;
  percentage: number;
};

export type PollResultsSummaryDto = {
  pollId: string;
  totalVotes: number;
  optionResults: PollOptionResultDto[];
  winningOptionId: string | null;
  winningOptionLabel: string | null;
  updatedAt: string;
};

export type PublicAuditTreeKind =
  | "nullifier"
  | "vote_commitment"
  | "encrypted_vote";

export type PublicAuditHashAlgorithm = "sha256" | "poseidon-bn254";

export type PublicAuditMerkleProofStepDto = {
  position: "left" | "right";
  hash: string;
};

export type PublicAuditTreeSummaryDto = {
  kind: PublicAuditTreeKind;
  root: string;
  leafCount: number;
  hashAlgorithm: PublicAuditHashAlgorithm;
  leafHashDomain: string;
  nodeHashDomain: string;
  treeDepth?: number;
  leafCapacity?: number;
};

export type PublicAuditComputedRootBatchDto = {
  status: "pending_on_chain_publication";
  batchIndex: number;
  acceptedCount: number;
  nullifierRoot: string;
  voteCommitmentRoot: string;
  encryptedVoteRoot: string;
  transactionSignature: string | null;
  explorerUrl: string | null;
  submittedAt: string | null;
};

export type PublicAuditRootCommitDto = {
  status: "published_on_chain";
  batchIndex: number;
  acceptedCount: number;
  nullifierRoot: string;
  voteCommitmentRoot: string;
  encryptedVoteRoot: string;
  transactionSignature: string;
  explorerUrl: string;
  submittedAt: string;
};

export type PublicAuditBatchSummaryDto = {
  batchIndex: number;
  acceptedCount: number;
  sealed: boolean;
  nullifierRoot: string;
  voteCommitmentRoot: string;
  encryptedVoteRoot: string;
  publication: PublicAuditRootCommitDto | null;
};

export type PublicAuditTallyProofSummaryDto = {
  resultHash: string;
  tallyProofHash: string;
  tallyPublicInputsHash: string;
  tallyVerifierKeyHash: string;
  tallyCircuitId: string;
  nullifierRoot: string;
  voteCommitmentRoot: string;
  encryptedVoteRoot: string;
  acceptedCount: number;
  verifiedAt: string;
};

export type PublicPollAuditDto = {
  version: "civicos-public-audit-v1";
  pollId: string;
  pollStatus: PollStatus;
  pollPolicyHash: string | null;
  credentialSchemaHash: string | null;
  optionSetHash: string | null;
  generatedAt: string;
  publicationStatus:
    | "not_applicable"
    | "pending_on_chain_publication"
    | "published_on_chain";
  acceptedVoteCount: number;
  totalValidVoteCount: number;
  trees: {
    nullifier: PublicAuditTreeSummaryDto;
    voteCommitment: PublicAuditTreeSummaryDto;
    encryptedVote: PublicAuditTreeSummaryDto;
  };
  auditBatches: PublicAuditBatchSummaryDto[];
  computedCurrentRootBatch: PublicAuditComputedRootBatchDto | null;
  rootCommits: PublicAuditRootCommitDto[];
  resultHash: string;
  tallyProofHash: string | null;
  tallyPublicInputsHash: string | null;
  tallyProof: PublicAuditTallyProofSummaryDto | null;
  finalResult: PollResultsSummaryDto;
  solana: {
    cluster: string;
    programId: string;
    transactionsEnabled: boolean;
  };
  inclusionCheck: {
    route: string;
    acceptedTrees: PublicAuditTreeKind[];
    expectsLeafHash: true;
  };
  warnings: string[];
};

export type PublicAuditInclusionProofSuccessDto = {
  success: true;
  pollId: string;
  tree: PublicAuditTreeKind;
  leafHash: string;
  batchIndex: number;
  leafIndex: number;
  matchingLeafCount: number;
  root: string;
  proof: PublicAuditMerkleProofStepDto[];
};

export type PublicAuditInclusionProofFailureDto = {
  success: false;
  errorCode: "POLL_NOT_FOUND" | "LEAF_NOT_FOUND";
  message: string;
};

export type PublicAuditInclusionProofResultDto =
  | PublicAuditInclusionProofSuccessDto
  | PublicAuditInclusionProofFailureDto;

export type PublicVoteReceiptLookupDto = {
  included: boolean;
  pollId: string;
  voteCommitment: string;
  voteCommitmentLeafHash: string;
  batchStatus:
    | "pending_on_chain_publication"
    | "published_on_chain"
    | "not_found";
  batchIndex: number | null;
  batchId: string | null;
  acceptedAt: string | null;
  proofHash: string | null;
  root: string | null;
  matchingLeafCount: number;
  merklePath: PublicAuditMerkleProofStepDto[];
  solanaTx: string | null;
  solanaExplorerUrl: string | null;
  auditUrl: string;
};

export type VoteReceiptDto = {
  version: "civicos-vote-receipt-v1";
  pollId: string;
  optionId: string;
  voteCommitment: string;
  voteCommitmentLeafHash: string;
  proofHash: string;
  batchStatus: "pending";
  batchId: string | null;
  solanaRootTransaction: string | null;
  acceptedAt: string;
  auditUrl: string;
};

export type PollSummaryDto = {
  poll: PollDto;
  optionCount: number;
  totalVotes: number;
  hasViewerVoted: boolean;
};

export type PollDetailsDto = {
  poll: PollDto;
  options: PollOptionDto[];
  viewerVote: ViewerVoteSummaryDto | null;
  totalVotes: number;
  results: PollResultsSummaryDto;
};

export type VoteSubmissionErrorCode =
  | "UNKNOWN_ERROR"
  | "USER_NOT_FOUND"
  | "IDENTITY_PROFILE_NOT_FOUND"
  | "HOME_LOCATION_MISSING"
  | "POLL_NOT_FOUND"
  | "POLL_NOT_ACTIVE"
  | "OPTION_NOT_FOUND"
  | "OPTION_NOT_IN_POLL"
  | "ALREADY_VOTED"
  | "ELIGIBILITY_FAILED"
  | "PROOF_REQUIRED"
  | "PROOF_INVALID";

export type VoteProofPublicInputsDto = {
  pollId: string;
  pollPolicyHash: string;
  credentialSchemaHash: string;
  nullifier: string;
  verificationMethodVersion: string;
  proofSystemVersion: string;
};

export type VoteProofEnvelopeDto = {
  version: string;
  proofSystemVersion: string;
  status: string;
  reason: string | null;
  publicInputs: VoteProofPublicInputsDto;
  publicInputsHash: string | null;
};

export type Groth16VoteProofPublicInputsDto = {
  version: string;
  pollId: string;
  pollPolicyHash: string;
  credentialSchemaHash: string;
  optionSetHash: string;
  optionCount: number;
  credentialRoot: string;
  nullifier: string;
  voteCommitment: string;
  encryptedVoteHash: string;
  encryptedVoteCommitment: string;
  verificationMethodVersion: string;
  proofSystemVersion: string;
  hashSuite: string;
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
};

export type Groth16VoteProofEnvelopeDto = {
  version: string;
  protocol: "groth16";
  proofSystemVersion: string;
  status: string;
  hashSuite: string;
  circuitId: string;
  verifierKeyHash: string;
  publicInputSchemaVersion: string;
  proof: unknown;
  publicInputs: Groth16VoteProofPublicInputsDto;
  publicInputsHash: string;
};

export type PreproverVotePrivacyPayloadDto = {
  version: string;
  hashSuite: string;
  nullifier: string;
  proof: VoteProofEnvelopeDto;
};

export type ProductionVotePrivacyPayloadDto = {
  version: string;
  votePrivacyMode: "zk_secret_ballot_v1";
  hashSuite: string;
  nullifier: string;
  voteCommitment: string;
  encryptedVoteHash: string;
  encryptedVoteCommitment: string;
  proof: Groth16VoteProofEnvelopeDto;
};

export type VotePrivacyPayloadDto =
  | PreproverVotePrivacyPayloadDto
  | ProductionVotePrivacyPayloadDto;

export type VoteSubmissionRequestDto = {
  optionId: string;
  privacy?: VotePrivacyPayloadDto | null;
  voteCommitment?: string | null;
  encryptedVote?: unknown;
  feeMode?: "civicos-sponsored" | "user-paid" | null;
};

export type VoteSubmissionSuccessDto = {
  success: true;
  viewerVote: ViewerVoteSummaryDto;
  receipt?: VoteReceiptDto | null;
};

export type VoteSubmissionFailureDto = {
  success: false;
  errorCode: VoteSubmissionErrorCode;
  reasonCode?: string | null;
  message: string;
};

export type VoteSubmissionResultDto = VoteSubmissionSuccessDto | VoteSubmissionFailureDto;

export type VerificationProofPublicInputsDto = {
  credentialCommitment: string;
  verificationMethodVersion: string;
};

export type VerificationProofRequestDto = {
  credentialSchemaHash: string;
  proof: unknown;
  publicInputs: VerificationProofPublicInputsDto;
};

export type CredentialIssuanceRequestDto = {
  credentialSchemaHash: string;
  credentialCommitment?: string | null;
};

export type CredentialIssuanceMaterialDto = {
  identityKeyHash: string;
  credentialSchemaHash: string;
  claimsHash: string;
  credentialIssuerId: string;
  commitmentScheme: "civicos-credential-commitment-v1";
  merkleDepth: 32;
};

export type IssuedCredentialRegistryDto = CredentialIssuanceMaterialDto & {
  credentialCommitment: string;
  credentialRoot: string;
  leafIndex: number;
  leafCount: number;
  credentialRootSiblings: string[];
  credentialRootPathIndices: number[];
  credentialRootCreatedAt: string;
};

export type CredentialIssuanceResultDto =
  | {
      success: true;
      status: "material";
      material: CredentialIssuanceMaterialDto;
    }
  | {
      success: true;
      status: "issued" | "existing";
      credential: IssuedCredentialRegistryDto;
    }
  | {
      success: false;
      errorCode:
        | "INVALID_INPUT"
        | "VERIFIED_IDENTITY_REQUIRED"
        | "IDENTITY_PROFILE_REQUIRED"
        | "CREDENTIAL_CONFLICT";
      message: string;
    };

export type ProofSystemPolicyDto = {
  version: "civicos-proof-system-policy-v1";
  phase: 11;
  selectedTrack: "v1";
  proofSystemVersion: "civicos-zk-proof-v1-preprover" | "civicos-zk-proof-v1";
  proofVerificationMode: "off_chain_preprover" | "off_chain_groth16";
  proofVerificationStatus: "preprover_accepted" | "verified";
  onChainZkVerifierEnabled: false;
  solanaAnchoring: "audit_roots_only";
  storesProofHash: true;
  storesPublicInputs: true;
  storesPrivateWitness: false;
  solanaArtifacts: Array<
    | "nullifier_root"
    | "vote_commitment_root"
    | "encrypted_vote_root"
    | "final_result_hash"
    | "tally_proof_hash"
    | "tally_public_inputs_hash"
  >;
  offChainArtifacts: Array<
    | "proof_hash"
    | "public_inputs"
    | "proof_envelope"
    | "groth16_proof"
    | "encrypted_vote"
    | "tally_proof"
  >;
  productionTarget: {
    enabled: boolean;
    verifierConfigured: boolean;
    proofSystemVersion: "civicos-zk-proof-v1";
    proofVerificationMode: "off_chain_groth16";
    proofVerificationStatus: "verified";
    hashSuite: "poseidon-bn254-v1";
    anonymousVoteTable: "poll_zk_votes";
    tallyProofRequired: true;
    onChainZkVerifierEnabled: false;
    artifactManifestConfigured: boolean;
    verifierKeyRegistryRecord: {
      version: "civicos-groth16-verifier-key-registry-v1";
      artifactKind: "vote" | "tally";
      proofSystem: "groth16";
      protocol: "groth16";
      curve: "bn254";
      hashSuite: "poseidon-bn254-v1";
      circuitId: string;
      verifierKeyHash: string;
      publicInputSchemaVersion: string;
      trustedSetupTranscriptHash: string;
      artifactManifestHash: string;
    } | null;
  };
  notes: string[];
};

export type VerificationProofResultDto =
  | {
      verified: true;
      credentialCommitment: string;
      credentialSchemaHash: string;
      verificationMethodVersion: string;
      proofVerificationMode: "off_chain_preprover";
      proofVerificationStatus: "preprover_accepted";
      expiresAt: string;
    }
  | {
      verified: false;
      errorCode: "INVALID_PROOF" | "UNSUPPORTED_VERSION";
      message: string;
    };

export type PollOptionInputDto =
  | string
  | {
      id?: string;
      label: string;
      description?: string | null;
      color?: string | null;
    };

export type CreatePollRequestDto = {
  title: string;
  description?: string | null;
  options: PollOptionInputDto[];
  jurisdictionType?: PollJurisdictionType;
  jurisdictionCountryCode?: string | null;
  jurisdictionAreaIds?: string[];
  jurisdictionLandIds?: string[];
  status?: PollStatus;
  eligibilityRule?: Partial<PollEligibilityRule> | null;
  votePrivacyMode?: PollVotePrivacyMode;
  pollEncryptionKeyId?: string | null;
};

export type UpdateDraftPollRequestDto = {
  pollId: string;
  title: string;
  description?: string | null;
  options: PollOptionInputDto[];
  jurisdictionType?: PollJurisdictionType;
  jurisdictionCountryCode?: string | null;
  jurisdictionAreaIds?: string[];
  jurisdictionLandIds?: string[];
  status?: "draft" | "active";
  eligibilityRule?: Partial<PollEligibilityRule> | null;
  votePrivacyMode?: PollVotePrivacyMode;
  pollEncryptionKeyId?: string | null;
};

export type PollManagementErrorCode =
  | "USER_NOT_FOUND"
  | "POLL_NOT_OWNED"
  | "VALIDATION_FAILED"
  | "POLL_NOT_FOUND"
  | "POLL_NOT_EDITABLE"
  | "POLL_ALREADY_HAS_VOTES";

export type CreatePollResultDto = {
  success: boolean;
  poll?: PollDto;
  options?: PollOptionDto[];
  errorCode?: PollManagementErrorCode;
  message?: string;
};

export type UpdateDraftPollResultDto = {
  success: boolean;
  poll?: PollDto;
  options?: PollOptionDto[];
  errorCode?: PollManagementErrorCode;
  message?: string;
};

export type PublishDraftPollResultDto = {
  success: boolean;
  poll?: PollDto;
  options?: PollOptionDto[];
  errorCode?: PollManagementErrorCode;
  message?: string;
};

export type PollEditabilityResultDto = {
  editable: boolean;
  errorCode?: PollManagementErrorCode;
  message?: string;
  voteCount?: number;
};

export type DraftPollEditorResultDto = {
  success: boolean;
  editable: boolean;
  poll?: PollDto;
  options?: PollOptionDto[];
  errorCode?: PollManagementErrorCode;
  message?: string;
  voteCount?: number;
};

export type ProvisionalUserBootstrapDto = {
  user: {
    id: string;
    onboardingStatus: string;
    verificationLevel: string;
    hasWallet: boolean;
    selectedLandId: string | null;
    isProvisional: boolean;
    createdAt: string;
    updatedAt: string;
  };
  identityProfile: {
    id: string;
    userId: string;
    hasHomeLocation: boolean;
    createdAt: string;
    updatedAt: string;
  };
};

export type AppUserDto = {
  id: string;
  username?: string;
  displayName?: string;
  publicNickname?: string;
  onboardingStatus: string;
  verificationLevel: string;
  hasWallet: boolean;
  walletCredentialId: string | null;
  selectedLandId: string | null;
  preferredLanguage?: string;
  createdAt: string;
  updatedAt: string;
};

export type ViewerProfileClaimsDto = {
  nickname?: string;
  profile_completed: boolean;
  passport_verified: boolean;
  face_verified: boolean;
};

export type WalletStatus = "not_created" | "local_only" | "issued";

export type BackendCredentialStatus = "not_issued" | "issued" | "revoked";

export type WalletCredentialDto = {
  id: string;
  userId: string;
  walletPublicId: string;
  holderId: string;
  backendCredentialStatus: BackendCredentialStatus;
  issuedAt: string | null;
  revokedAt: string | null;
};

export type ViewerWalletStateDto = {
  exists: boolean;
  status: WalletStatus;
  backendCredentialStatus: BackendCredentialStatus;
  credentialId: string | null;
  walletPublicId: string | null;
  issuedAt: string | null;
  revokedAt: string | null;
};

export type IssuedWalletCredentialDto = {
  id: string;
  issuer: string;
  type: "IlandIdentityCredential";
  version: "0.0.86";
  subjectId: string;
  holderId: string;
  walletPublicId: string;
  walletPublicKey: string;
  verifiedIdentity: boolean;
  status: "issued";
  issuedAt: string;
  proof: {
    type: "hmac_sha256";
    value: string;
  };
};

export type IssueWalletCredentialRequestDto = {
  walletPublicId: string;
  holderId: string;
  walletPublicKey: string;
};

export type IssueWalletCredentialErrorCode =
  | "USER_NOT_FOUND"
  | "INVALID_INPUT"
  | "IDENTITY_PROFILE_REQUIRED"
  | "VERIFIED_IDENTITY_REQUIRED"
  | "CREDENTIAL_REVOKED";

export type IssueWalletCredentialResultDto =
  | {
      success: true;
      wallet: ViewerWalletStateDto;
      walletCredential: WalletCredentialDto;
      issuedCredential: IssuedWalletCredentialDto;
    }
  | {
      success: false;
      wallet: ViewerWalletStateDto;
      walletCredential: WalletCredentialDto | null;
      errorCode: IssueWalletCredentialErrorCode;
      message: string;
    };

export type BindVerifiedIdentityRequestDto = {
  // Device-side hash: SHA-512(normalized_nidn)
  nidnh: string;
  normalizationVersion: number;
  verificationMethod?: "passport_nfc";
  verificationEvidence: {
    liveness: {
      passed: true;
      [key: string]: unknown;
    };
    likeness: {
      passed: true;
      similarity: number;
      threshold: number;
      [key: string]: unknown;
    };
    gaze?: {
      passed: true;
      [key: string]: unknown;
    };
  };
};

export type VerifiedIdentityBindingDto = {
  id: string;
  userId: string;
  normalizationVersion: number;
  verificationMethod: string;
  verifiedAt: string;
  createdAt: string;
  updatedAt: string;
};

export type BindVerifiedIdentityErrorCode =
  | "USER_NOT_FOUND"
  | "INVALID_INPUT"
  | "IDENTITY_ALREADY_BOUND";

export type BindVerifiedIdentityStatus =
  | "bound_new"
  | "bound_existing_same_user"
  | "recovered_existing_user";

export type BindVerifiedIdentityResultDto =
  | {
      success: true;
      status: BindVerifiedIdentityStatus;
      authoritativeUserId: string;
      verifiedIdentity: VerifiedIdentityBindingDto;
    }
  | {
      success: false;
      errorCode: BindVerifiedIdentityErrorCode;
      message: string;
    };

export type IdentityProfileDto = {
  id: string;
  userId: string;
  passportScanCompleted: boolean;
  passportNfcCompleted: boolean;
  nationalIdScanCompleted: boolean;
  faceScanCompleted: boolean;
  faceBoundToIdentity: boolean;
  passportVerifiedAt: string | null;
  nationalIdVerifiedAt: string | null;
  faceVerifiedAt: string | null;
  documentCountryCode: string | null;
  issuingCountryCode: string | null;
  homeLocation: {
    countryCode: string;
    areaId: string;
    approxLatitude: number | null;
    approxLongitude: number | null;
    source: string;
    updatedAt: string;
  } | null;
  createdAt: string;
  updatedAt: string;
} | null;

export type LandDto = {
  id: string;
  name: string;
  slug: string;
  type: string;
  flagType: string;
  flagAsset: string | null;
  flagEmoji: string | null;
  founderUserId: string | null;
  description: string | null;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
};

export type GeoAreaOptionDto = {
  id: string;
  level: string;
  countryCode: string;
  centerLatitude: number;
  centerLongitude: number;
  parentAreaId: string | null;
  label: string | null;
  isActive: boolean;
};

export type CurrentViewerProfileDto = {
  user: AppUserDto;
  claims: ViewerProfileClaimsDto;
  identityProfile: IdentityProfileDto;
  homeArea: GeoAreaOptionDto | null;
  wallet: ViewerWalletStateDto;
  walletCredential: WalletCredentialDto | null;
  selectedLand: LandDto | null;
  primaryCitizenship: null;
};

export type ViewerLandStateDto = {
  selectedLandId: string | null;
  selectedLand: LandDto | null;
  lands: LandDto[];
};

export type ViewerLandSelectionResultDto = {
  success: boolean;
  profile?: CurrentViewerProfileDto;
  state?: ViewerLandStateDto;
  land?: LandDto | null;
  errorCode?: "USER_NOT_FOUND" | "LAND_NOT_FOUND" | "INVALID_INPUT";
  message?: string;
};

export type UpdateViewerHomeLocationRequestDto = {
  approxLatitude: number;
  approxLongitude: number;
  source?: "user_selected" | "derived_from_document" | "admin_set" | "mock";
  countryCode?: string | null;
  areaId?: string | null;
};

export type UpdateViewerHomeLocationResultDto = {
  success: boolean;
  profile?: CurrentViewerProfileDto;
  errorCode?:
    | "USER_NOT_FOUND"
    | "IDENTITY_PROFILE_NOT_FOUND"
    | "INVALID_COORDINATES"
    | "INVALID_INPUT";
  message?: string;
};

export type UpdateViewerPublicNicknameRequestDto = {
  publicNickname: string;
};

export type UpdateViewerPublicNicknameResultDto = {
  success: boolean;
  profile?: CurrentViewerProfileDto;
  errorCode?: "USER_NOT_FOUND" | "INVALID_NICKNAME" | "NICKNAME_TAKEN";
  message?: string;
};

export type PollCreationCountryOptionDto = {
  value: string;
  label: string;
};

export type PollCreationReferenceDataDto = {
  lands: LandDto[];
  areaOptions: GeoAreaOptionDto[];
  countryOptions: PollCreationCountryOptionDto[];
};

export type MapAreaLevel = "city" | "country";
export const MAP_ALL_POLLS_SCOPE_ID = "all_polls" as const;

export type GetPollVoteMapMarkersRequestDto = {
  // Use MAP_ALL_POLLS_SCOPE_ID for aggregate all-polls map mode.
  pollId: string;
  areaLevel?: MapAreaLevel;
  parentAreaId?: string | null;
  countryCode?: string | null;
  includeEmptyAreas?: boolean;
};

export type VoteMapMarkerOptionBreakdownDto = {
  optionId: string;
  label: string;
  count: number;
  color: string | null;
  percentageWithinArea: number;
};

export type VoteMapMarkerPrivacyDto = {
  thresholdK: number;
  mergeStrategy: "hierarchical_parent_k";
  mergedFromAreaIds: string[];
  mergedAreaCount: number;
  maxMergeDepth: number;
};

export type VoteMapMarkerDto = {
  id: string;
  // For all-polls aggregate markers, this is MAP_ALL_POLLS_SCOPE_ID.
  pollId: string;
  areaId: string;
  areaLevel: MapAreaLevel;
  parentAreaId: string | null;
  latitude: number;
  longitude: number;
  totalVotes: number;
  optionBreakdown: VoteMapMarkerOptionBreakdownDto[];
  leadingOptionId: string | null;
  leadingOptionLabel: string | null;
  leadingOptionColor: string | null;
  leadingOptionCount: number | null;
  leadingOptionPercentage: number | null;
  mergedAreaCount: number;
  privacy: VoteMapMarkerPrivacyDto;
  updatedAt: string;
};

export type GetPollVoteMapMarkersResponseDto = VoteMapMarkerDto[];
