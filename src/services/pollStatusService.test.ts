import { describe, expect, it } from "bun:test";

import { resolveEffectivePollStatus } from "./pollStatusService";

describe("poll status resolution", () => {
  it("treats an active poll as closed when ends_at has passed", () => {
    expect(
      resolveEffectivePollStatus(
        {
          status: "active",
          starts_at: null,
          ends_at: "2026-01-01T00:00:00.000Z",
        },
        "2026-01-01T00:00:00.000Z",
      ),
    ).toBe("closed");
  });

  it("treats a scheduled poll as active after starts_at until ends_at", () => {
    expect(
      resolveEffectivePollStatus(
        {
          status: "scheduled",
          starts_at: "2026-01-01T00:00:00.000Z",
          ends_at: "2026-01-02T00:00:00.000Z",
        },
        "2026-01-01T12:00:00.000Z",
      ),
    ).toBe("active");
  });
});
