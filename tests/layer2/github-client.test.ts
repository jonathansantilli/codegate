import { mkdtempSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createGithubMetadataClient } from "../../src/layer2-static/github/client";
import { saveCachedAdvisoryPayload } from "../../src/layer2-static/github/cache";

describe("github metadata client", () => {
  it("defaults to offline-safe metadata loading", () => {
    const client = createGithubMetadataClient();

    expect(client.runtimeMode).toBe("offline");
    expect(client.isOnlineEnabled()).toBe(false);
    expect(client.cacheDir).toBe(join(homedir(), ".codegate", "cache"));
  });

  it("does not enable online metadata in online-no-audits mode", () => {
    const client = createGithubMetadataClient({ runtimeMode: "online-no-audits" });

    expect(client.isOnlineEnabled()).toBe(false);
  });

  it("returns a fresh cached payload in online mode", () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "codegate-github-client-cache-"));
    const now = 1_000_000;
    const payload = {
      generatedAt: now,
      advisories: {
        "actions/checkout": ["v3"],
      },
    };

    saveCachedAdvisoryPayload(cacheDir, payload);

    const client = createGithubMetadataClient({
      runtimeMode: "online",
      cacheDir,
      now,
      cacheMaxAgeMs: 60_000,
    });

    expect(
      client.loadKnownVulnerableActions({
        "actions/checkout": ["v4"],
      }),
    ).toEqual(payload);
  });
});
