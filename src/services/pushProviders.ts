import { createSign } from "node:crypto";
import { connect, type ClientHttp2Session } from "node:http2";
import env from "../config/env";

export type PushSendResult = {
  outcome: "sent" | "retry" | "invalid_token" | "dead";
  messageId?: string | null;
  errorCode?: string | null;
  errorMessage?: string | null;
};

type PushMessage = {
  token: string;
  environment: "sandbox" | "production";
  title: string;
  body: string;
  notificationId: string;
  eventType: string;
  targetUrl: string;
};

const base64urlJson = (value: unknown): string =>
  Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

let cachedApnsJwt: { token: string; expiresAt: number } | null = null;
const apnsSessions = new Map<string, ClientHttp2Session>();

const getApnsJwt = (): string => {
  if (cachedApnsJwt && cachedApnsJwt.expiresAt > Date.now()) {
    return cachedApnsJwt.token;
  }
  if (!env.notifications.apns.configured) {
    throw new Error("APNs credentials are not configured.");
  }
  const issuedAt = Math.floor(Date.now() / 1000);
  const header = base64urlJson({ alg: "ES256", kid: env.notifications.apns.keyId });
  const claims = base64urlJson({ iss: env.notifications.apns.teamId, iat: issuedAt });
  const signingInput = `${header}.${claims}`;
  const signer = createSign("SHA256");
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(
    {
      key: env.notifications.apns.privateKey as string,
      dsaEncoding: "ieee-p1363",
    },
  );
  cachedApnsJwt = {
    token: `${signingInput}.${signature.toString("base64url")}`,
    expiresAt: Date.now() + 50 * 60 * 1000,
  };
  return cachedApnsJwt.token;
};

const getApnsSession = (origin: string): ClientHttp2Session => {
  const existing = apnsSessions.get(origin);
  if (existing && !existing.closed && !existing.destroyed) return existing;
  const session = connect(origin);
  session.on("error", () => {
    if (apnsSessions.get(origin) === session) apnsSessions.delete(origin);
  });
  session.on("close", () => {
    if (apnsSessions.get(origin) === session) apnsSessions.delete(origin);
  });
  apnsSessions.set(origin, session);
  return session;
};

const classifyApns = (
  status: number,
  reason: string | null,
  messageId: string | null,
): PushSendResult => {
  if (status === 200) return { outcome: "sent", messageId };
  if (reason === "BadDeviceToken" || reason === "Unregistered" || reason === "DeviceTokenNotForTopic") {
    return { outcome: "invalid_token", errorCode: reason, errorMessage: reason };
  }
  if (status === 429 || status >= 500) {
    return { outcome: "retry", errorCode: reason || `apns_${status}`, errorMessage: reason };
  }
  return { outcome: "dead", errorCode: reason || `apns_${status}`, errorMessage: reason };
};

export const sendApnsPush = async (message: PushMessage): Promise<PushSendResult> => {
  if (!env.notifications.apns.configured) {
    return { outcome: "dead", errorCode: "apns_not_configured" };
  }
  const origin = message.environment === "sandbox"
    ? "https://api.sandbox.push.apple.com"
    : "https://api.push.apple.com";
  try {
    return await new Promise<PushSendResult>((resolve, reject) => {
      const request = getApnsSession(origin).request({
        ":method": "POST",
        ":path": `/3/device/${message.token}`,
        authorization: `bearer ${getApnsJwt()}`,
        "content-type": "application/json",
        "apns-topic": env.notifications.apns.bundleId as string,
        "apns-push-type": "alert",
        "apns-priority": "10",
      });
      const chunks: Buffer[] = [];
      let status = 0;
      let messageId: string | null = null;
      request.setEncoding("utf8");
      request.on("response", (headers) => {
        status = Number(headers[":status"] || 0);
        messageId = typeof headers["apns-id"] === "string" ? headers["apns-id"] : null;
      });
      request.on("data", (chunk: string) => chunks.push(Buffer.from(chunk)));
      request.on("error", reject);
      request.on("end", () => {
        let reason: string | null = null;
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          reason = typeof parsed.reason === "string" ? parsed.reason : null;
        } catch {
          // Successful APNs responses have an empty body.
        }
        resolve(classifyApns(status, reason, messageId));
      });
      request.end(
        JSON.stringify({
          aps: {
            alert: { title: message.title, body: message.body },
            sound: "default",
          },
          notificationId: message.notificationId,
          eventType: message.eventType,
          url: message.targetUrl,
        }),
      );
    });
  } catch (error) {
    return {
      outcome: "retry",
      errorCode: "apns_transport_error",
      errorMessage: error instanceof Error ? error.message : "APNs transport failed.",
    };
  }
};

let cachedFcmAccessToken: { token: string; expiresAt: number } | null = null;

const getFcmAccessToken = async (): Promise<string> => {
  if (cachedFcmAccessToken && cachedFcmAccessToken.expiresAt > Date.now()) {
    return cachedFcmAccessToken.token;
  }
  if (!env.notifications.fcm.configured) {
    throw new Error("FCM credentials are not configured.");
  }
  const now = Math.floor(Date.now() / 1000);
  const header = base64urlJson({ alg: "RS256", typ: "JWT" });
  const claims = base64urlJson({
    iss: env.notifications.fcm.clientEmail,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  });
  const signingInput = `${header}.${claims}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  const assertion = `${signingInput}.${signer
    .sign(env.notifications.fcm.privateKey as string)
    .toString("base64url")}`;
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  const payload = await response.json() as {
    access_token?: string;
    expires_in?: number;
    error_description?: string;
  };
  if (!response.ok || !payload.access_token) {
    throw new Error(payload.error_description || `FCM OAuth failed (${response.status}).`);
  }
  cachedFcmAccessToken = {
    token: payload.access_token,
    expiresAt: Date.now() + Math.max(60, (payload.expires_in || 3600) - 300) * 1000,
  };
  return payload.access_token;
};

export const sendFcmPush = async (message: PushMessage): Promise<PushSendResult> => {
  if (!env.notifications.fcm.configured) {
    return { outcome: "dead", errorCode: "fcm_not_configured" };
  }
  try {
    const response = await fetch(
      `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(env.notifications.fcm.projectId as string)}/messages:send`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${await getFcmAccessToken()}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          message: {
            token: message.token,
            notification: { title: message.title, body: message.body },
            data: {
              notificationId: message.notificationId,
              eventType: message.eventType,
              url: message.targetUrl,
            },
            android: {
              priority: "high",
              notification: { channel_id: "civic_activity", sound: "default" },
            },
          },
        }),
      },
    );
    const payload = await response.json().catch(() => ({})) as {
      name?: string;
      error?: { status?: string; message?: string; details?: Array<{ errorCode?: string }> };
    };
    if (response.ok) return { outcome: "sent", messageId: payload.name || null };
    const detailCode = payload.error?.details?.find((detail) => detail.errorCode)?.errorCode;
    const code = detailCode || payload.error?.status || `fcm_${response.status}`;
    if (detailCode === "UNREGISTERED" || detailCode === "INVALID_ARGUMENT") {
      return { outcome: "invalid_token", errorCode: code, errorMessage: payload.error?.message };
    }
    if (response.status === 429 || response.status >= 500) {
      return { outcome: "retry", errorCode: code, errorMessage: payload.error?.message };
    }
    return { outcome: "dead", errorCode: code, errorMessage: payload.error?.message };
  } catch (error) {
    cachedFcmAccessToken = null;
    return {
      outcome: "retry",
      errorCode: "fcm_transport_error",
      errorMessage: error instanceof Error ? error.message : "FCM transport failed.",
    };
  }
};

export default { sendApnsPush, sendFcmPush };
