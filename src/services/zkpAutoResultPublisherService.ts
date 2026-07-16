import { env } from "../config/env";
import pollAuditRepository from "../repositories/pollAuditRepository";
import pollRepository from "../repositories/pollRepository";
import zkpTallyJobRepository from "../repositories/zkpTallyJobRepository";
import type { PollRow, ZkpTallyJobRow } from "../types/db";
import pollPublicAuditService from "./pollPublicAuditService";

const FINAL_RESULT_EVENT_TYPE = "poll_final_result_published_on_chain";
const DEFAULT_INTERVAL_MS = 15_000;
const DEFAULT_LIMIT = 25;

export type ZkpAutoResultPublisherDependencies = Readonly<{
  tallyJobRepositoryLike?: Pick<typeof zkpTallyJobRepository, "listSucceeded">;
  pollRepositoryLike?: Pick<typeof pollRepository, "getById" | "closeExpiredPolls">;
  pollAuditRepositoryLike?: Pick<
    typeof pollAuditRepository,
    "getLatestAuditEventByPollIdAndType"
  >;
  publicAuditServiceLike?: Pick<typeof pollPublicAuditService, "publishPollAudit">;
  setIntervalFn?: typeof setInterval;
  clearIntervalFn?: typeof clearInterval;
}>;

const toErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const isAutoPublishablePoll = (poll: PollRow | null): poll is PollRow =>
  Boolean(
    poll &&
      poll.created_by_user_id &&
      poll.result_publication_mode === "auto_on_close" &&
      poll.vote_privacy_mode === "zk_secret_ballot_v1" &&
      (poll.status === "closed" || poll.status === "archived"),
  );

export const createZkpAutoResultPublisherService = (
  dependencies: ZkpAutoResultPublisherDependencies = {},
) => {
  const tallyJobs = dependencies.tallyJobRepositoryLike ?? zkpTallyJobRepository;
  const polls = dependencies.pollRepositoryLike ?? pollRepository;
  const auditEvents = dependencies.pollAuditRepositoryLike ?? pollAuditRepository;
  const publicAudit = dependencies.publicAuditServiceLike ?? pollPublicAuditService;
  const setIntervalImpl = dependencies.setIntervalFn ?? setInterval;
  const clearIntervalImpl = dependencies.clearIntervalFn ?? clearInterval;
  let intervalId: ReturnType<typeof setInterval> | null = null;
  let running = false;

  const processJob = async (job: ZkpTallyJobRow): Promise<boolean> => {
    const poll = await polls.getById(job.poll_id);
    if (!isAutoPublishablePoll(poll)) {
      return false;
    }

    const existingFinalResult =
      await auditEvents.getLatestAuditEventByPollIdAndType(
        poll.id,
        FINAL_RESULT_EVENT_TYPE,
      );
    if (existingFinalResult) {
      return false;
    }

    const ownerUserId = poll.created_by_user_id;
    if (!ownerUserId) {
      return false;
    }

    const publication = await publicAudit.publishPollAudit({
      pollId: poll.id,
      viewerUserId: ownerUserId,
    });
    if (!publication.success) {
      console.warn("[zkpAutoResultPublisher] publication failed", {
        pollId: poll.id,
        errorCode: publication.errorCode,
        message: publication.message,
      });
      return false;
    }

    console.info("[zkpAutoResultPublisher] published final result", {
      pollId: poll.id,
      message: publication.message,
    });
    return true;
  };

  const runCycle = async (): Promise<{ scanned: number; published: number }> => {
    await polls.closeExpiredPolls();
    const jobs = await tallyJobs.listSucceeded({ limit: DEFAULT_LIMIT });
    let published = 0;

    for (const job of jobs) {
      if (await processJob(job)) {
        published += 1;
      }
    }

    return {
      scanned: jobs.length,
      published,
    };
  };

  return {
    async runCycle() {
      return runCycle();
    },

    start() {
      if (intervalId) {
        return;
      }

      intervalId = setIntervalImpl(() => {
        if (running) {
          return;
        }

        running = true;
        void runCycle()
          .catch((error) => {
            console.error("[zkpAutoResultPublisher] cycle failed", {
              message: toErrorMessage(error),
            });
          })
          .finally(() => {
            running = false;
          });
      }, Math.max(env.zkp.tallyWorker.pollIntervalMs, DEFAULT_INTERVAL_MS));

      console.info("[zkpAutoResultPublisher] started");
      void runCycle().catch((error) => {
        console.error("[zkpAutoResultPublisher] initial cycle failed", {
          message: toErrorMessage(error),
        });
      });
    },

    stop() {
      if (!intervalId) {
        return;
      }

      clearIntervalImpl(intervalId);
      intervalId = null;
      console.info("[zkpAutoResultPublisher] stopped");
    },
  };
};

export default createZkpAutoResultPublisherService;
