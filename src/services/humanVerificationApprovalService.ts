import { timingSafeEqual } from "node:crypto";

import { hashOpaqueBearerToken } from "../auth/tokens";
import humanVerificationRepository from "../repositories/humanVerificationRepository";
import { requireSupabaseAdminClient } from "../db/supabaseClient";

type Dependencies = {
  repositoryLike?: typeof humanVerificationRepository;
  now?: () => Date;
};

const hashesMatch = (left: string, right: string): boolean => {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
};

export const createHumanVerificationApprovalService = (
  dependencies: Dependencies = {},
) => {
  const repository =
    dependencies.repositoryLike || humanVerificationRepository;
  const now = dependencies.now || (() => new Date());

  const validate = async (input: {
    requestId: string;
    reviewToken: string;
    credentialId: string;
    publicKeyPem: string;
  }) => {
    const request = await repository.getRequestById(input.requestId);
    if (
      !request ||
      request.status !== "approved" ||
      new Date(request.expires_at).getTime() <= now().getTime() ||
      request.device_credential_id !== input.credentialId ||
      request.device_public_key_pem.trim() !== input.publicKeyPem.trim() ||
      !hashesMatch(
        request.access_token_hash,
        hashOpaqueBearerToken(input.reviewToken),
      )
    ) {
      return {
        success: false as const,
        errorCode: "HUMAN_REVIEW_NOT_APPROVED",
        message:
          "The human-verification approval is missing, expired, or belongs to another device.",
      };
    }
    return { success: true as const, request };
  };

  return {
    validate,

    async consume(input: {
      requestId: string;
      reviewToken: string;
      credentialId: string;
      publicKeyPem: string;
    }) {
      const approval = await validate(input);
      if (!approval.success) return approval;
      const request = approval.request;

      const consumed = await repository.transitionRequest(
        request.id,
        "approved",
        "consumed",
        { consumed_at: now().toISOString() },
      );
      return consumed
        ? { success: true as const, request: consumed }
        : {
            success: false as const,
            errorCode: "HUMAN_REVIEW_ALREADY_USED",
            message: "The human-verification approval has already been used.",
          };
    },

    associateUser(requestId: string, userId: string) {
      return repository.associateConsumedUser(requestId, userId);
    },

    async deleteConsumedMedia(requestId: string) {
      const request = await repository.getRequestById(requestId);
      if (!request || request.status !== "consumed") return;
      const media = await repository.listMedia(requestId);
      for (const item of media) {
        if (item.upload_status === "deleted") continue;
        const { error } = await requireSupabaseAdminClient()
          .storage.from(item.storage_bucket)
          .remove([item.storage_path]);
        if (!error) {
          await repository.markMediaDeleted(item.id);
        }
      }
    },
  };
};

export const humanVerificationApprovalService =
  createHumanVerificationApprovalService();

export default humanVerificationApprovalService;
