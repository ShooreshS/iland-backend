import type { PollStatus } from "../types/contracts";
import type { PollRow } from "../types/db";

const timestampMs = (value: string | null | undefined): number | null => {
  if (!value) {
    return null;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
};

export const resolveEffectivePollStatus = (
  poll: Pick<PollRow, "status" | "starts_at" | "ends_at">,
  now: Date | string = new Date(),
): PollStatus => {
  if (poll.status === "draft" || poll.status === "archived") {
    return poll.status;
  }

  if (poll.status === "closed") {
    return "closed";
  }

  const nowMs =
    typeof now === "string" ? timestampMs(now) : Number.isFinite(now.getTime()) ? now.getTime() : null;
  if (nowMs === null) {
    return poll.status;
  }

  const endsAtMs = timestampMs(poll.ends_at);
  if (endsAtMs !== null && endsAtMs <= nowMs) {
    return "closed";
  }

  const startsAtMs = timestampMs(poll.starts_at);
  if (startsAtMs !== null && startsAtMs > nowMs) {
    return "scheduled";
  }

  if (poll.status === "scheduled") {
    return "active";
  }

  return poll.status;
};
