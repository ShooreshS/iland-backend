import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { decryptPushToken, encryptPushToken, hashPushToken } from "./pushTokenCrypto";
import { renderPushMessage } from "./pushMessageRenderer";

describe("notification feature", () => {
  it("encrypts device tokens at rest and detects ciphertext tampering", () => {
    const key = Buffer.alloc(32, 7).toString("base64");
    const token = "native-device-token";
    const encrypted = encryptPushToken(token, key);

    expect(encrypted).not.toContain(token);
    expect(decryptPushToken(encrypted, key)).toBe(token);
    expect(hashPushToken(token)).toHaveLength(64);
    expect(() => decryptPushToken(`${encrypted}x`, key)).toThrow();
  });

  it("renders localized, aggregated like copy without discussion content", () => {
    expect(
      renderPushMessage({
        eventType: "discussion.post_liked",
        aggregationCount: 4,
        locale: "sv-SE",
        actorPublicNickname: "alice",
      }),
    ).toEqual({
      title: "CivicOS",
      body: "Ditt inlägg fick 4 nya gilla-markeringar.",
    });
  });

  it("migration materializes only the four v1 discussion events", () => {
    const migration = readFileSync(
      resolve(
        process.cwd(),
        "supabase/migrations/20260826120000_add_discussion_notifications.sql",
      ),
      "utf8",
    );
    for (const eventType of [
      "discussion.post_commented",
      "discussion.comment_replied",
      "discussion.post_liked",
      "discussion.comment_liked",
    ]) {
      expect(migration).toContain(eventType);
    }
    expect(migration).not.toContain("poll.vote_cast");
    expect(migration).not.toContain("discussion.post_reported");
    expect(migration).toContain("for update skip locked");
    expect(migration).toContain("pg_advisory_xact_lock");
    expect(migration).toContain("interval '15 minutes'");
  });
});
