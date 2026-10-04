import humanVerificationService from "./humanVerificationService";

const RETENTION_INTERVAL_MS = 60 * 60 * 1000;

export const createHumanVerificationRetentionWorker = () => {
  let running = false;
  let timer: ReturnType<typeof setInterval> | null = null;

  const runOnce = async () => {
    if (running) return { expired: 0, deleted: 0 };
    running = true;
    try {
      return await humanVerificationService.cleanupExpiredAndRetainedMedia();
    } finally {
      running = false;
    }
  };

  return {
    runOnce,
    start() {
      if (timer) return;
      void runOnce().catch((error) => {
        console.error("[humanVerificationRetentionWorker] cleanup failed", {
          message: error instanceof Error ? error.message : "Unknown cleanup failure",
        });
      });
      timer = setInterval(() => {
        void runOnce().catch((error) => {
          console.error("[humanVerificationRetentionWorker] cleanup failed", {
            message: error instanceof Error ? error.message : "Unknown cleanup failure",
          });
        });
      }, RETENTION_INTERVAL_MS);
      timer.unref?.();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
};

export default createHumanVerificationRetentionWorker;
