import { randomUUID } from "node:crypto";
import env from "../config/env";
import notificationRepository, {
  type ClaimedPushDelivery,
} from "../repositories/notificationRepository";
import { decryptPushToken } from "./pushTokenCrypto";
import { renderPushMessage } from "./pushMessageRenderer";
import { sendApnsPush, sendFcmPush } from "./pushProviders";

const retryAt = (attempt: number): string => {
  const exponent = Math.max(0, Math.min(8, attempt - 1));
  const delay = env.notifications.delivery.retryBaseMs * 2 ** exponent;
  const jitter = Math.floor(Math.random() * Math.min(delay * 0.2, 5_000));
  return new Date(Date.now() + delay + jitter).toISOString();
};

const deliver = async (delivery: ClaimedPushDelivery): Promise<void> => {
  if (!env.notifications.tokenEncryptionKey) {
    throw new Error("Push token encryption key is unavailable.");
  }
  let token: string;
  try {
    token = decryptPushToken(
      delivery.token_ciphertext,
      env.notifications.tokenEncryptionKey,
    );
  } catch (error) {
    await notificationRepository.completeDelivery({
      deliveryId: delivery.delivery_id,
      status: "dead",
      errorCode: "token_decryption_failed",
      errorMessage: error instanceof Error ? error.message : "Token decryption failed.",
    });
    return;
  }

  const copy = renderPushMessage({
    eventType: delivery.event_type,
    aggregationCount: delivery.aggregation_count,
    locale: delivery.locale,
    actorPublicNickname: delivery.payload?.actorPublicNickname,
  });
  const result = delivery.provider === "apns"
    ? await sendApnsPush({
        token,
        environment: delivery.provider_environment,
        ...copy,
        notificationId: delivery.notification_id,
        eventType: delivery.event_type,
        targetUrl: delivery.target_url,
      })
    : await sendFcmPush({
        token,
        environment: delivery.provider_environment,
        ...copy,
        notificationId: delivery.notification_id,
        eventType: delivery.event_type,
        targetUrl: delivery.target_url,
      });

  if (result.outcome === "sent") {
    await notificationRepository.completeDelivery({
      deliveryId: delivery.delivery_id,
      status: "sent",
      providerMessageId: result.messageId,
    });
    await notificationRepository.markInstallationSuccessful(
      delivery.installation_id,
    );
    return;
  }

  if (result.outcome === "invalid_token") {
    await notificationRepository.completeDelivery({
      deliveryId: delivery.delivery_id,
      status: "invalid_token",
      errorCode: result.errorCode,
      errorMessage: result.errorMessage,
    });
    await notificationRepository.markInstallationInvalid(delivery.installation_id);
    return;
  }

  const exhausted = delivery.attempt_count >= env.notifications.delivery.maxAttempts;
  await notificationRepository.completeDelivery({
    deliveryId: delivery.delivery_id,
    status: result.outcome === "retry" && !exhausted ? "retry" : "dead",
    errorCode: exhausted ? "max_attempts_exhausted" : result.errorCode,
    errorMessage: result.errorMessage,
    availableAt: result.outcome === "retry" && !exhausted
      ? retryAt(delivery.attempt_count)
      : null,
  });
};

export const createNotificationDeliveryWorker = () => {
  const workerId = `notification-${process.pid}-${randomUUID()}`;
  let timer: ReturnType<typeof setInterval> | null = null;
  let running = false;

  const runOnce = async (): Promise<number> => {
    if (running) return 0;
    running = true;
    try {
      const deliveries = await notificationRepository.claimDeliveries({
        workerId,
        batchSize: env.notifications.delivery.batchSize,
        lockTimeoutSeconds: env.notifications.delivery.lockTimeoutSeconds,
      });
      await Promise.all(
        deliveries.map(async (delivery) => {
          try {
            await deliver(delivery);
          } catch (error) {
            console.error("[notificationDeliveryWorker] delivery failed", {
              deliveryId: delivery.delivery_id,
              error: error instanceof Error ? error.message : "Unknown failure",
            });
            await notificationRepository.completeDelivery({
              deliveryId: delivery.delivery_id,
              status:
                delivery.attempt_count >= env.notifications.delivery.maxAttempts
                  ? "dead"
                  : "retry",
              errorCode: "worker_error",
              errorMessage:
                error instanceof Error ? error.message : "Notification worker failed.",
              availableAt: retryAt(delivery.attempt_count),
            });
          }
        }),
      );
      return deliveries.length;
    } finally {
      running = false;
    }
  };

  return {
    runOnce,
    start() {
      if (timer) return;
      void runOnce();
      timer = setInterval(() => void runOnce(), env.notifications.delivery.intervalMs);
      timer.unref?.();
      console.info("[notificationDeliveryWorker] started", { workerId });
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
};

export default createNotificationDeliveryWorker;
