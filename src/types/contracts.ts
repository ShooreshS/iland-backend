export const VOTING_CONTRACT_VERSION = "0.0.86" as const;

export type PollStatus = "draft" | "scheduled" | "active" | "closed" | "archived";

export type PollJurisdictionType =
  | "global"
  | "real_country"
  | "real_area"
  | "land";

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
  startsAt: string | null;
  endsAt: string | null;
  createdAt: string;
  updatedAt: string;
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
  | "ELIGIBILITY_FAILED";

export type VoteSubmissionSuccessDto = {
  success: true;
  viewerVote: ViewerVoteSummaryDto;
};

export type VoteSubmissionFailureDto = {
  success: false;
  errorCode: VoteSubmissionErrorCode;
  message: string;
};

export type VoteSubmissionResultDto = VoteSubmissionSuccessDto | VoteSubmissionFailureDto;

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
  onboardingStatus: string;
  verificationLevel: string;
  hasWallet: boolean;
  walletCredentialId: string | null;
  selectedLandId: string | null;
  preferredLanguage?: string;
  createdAt: string;
  updatedAt: string;
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

export type IdentityProfileDto = {
  id: string;
  userId: string;
  passportScanCompleted: boolean;
  passportNfcCompleted: boolean;
  nationalIdScanCompleted: boolean;
  faceScanCompleted: boolean;
  faceBoundToIdentity: boolean;
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

export type GetPollVoteMapMarkersRequestDto = {
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

// 0.0.86: backend map retrieval is poll-scoped only; all-polls mode is deferred.
export type GetPollVoteMapMarkersResponseDto = VoteMapMarkerDto[];
