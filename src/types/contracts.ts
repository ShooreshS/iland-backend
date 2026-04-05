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
