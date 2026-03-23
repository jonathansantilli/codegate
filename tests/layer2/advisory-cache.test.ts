import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  loadCachedAdvisoryPayload,
  resolveGithubMetadataCachePath,
  saveCachedAdvisoryPayload,
} from "../../src/layer2-static/github/cache";

describe("advisory cache", () => {
  it("saves and loads cached advisory payloads", () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "codegate-advisory-cache-"));
    const payload = {
      generatedAt: Date.now(),
      advisories: {
        "actions/checkout": ["v3"],
      },
    };

    saveCachedAdvisoryPayload(cacheDir, payload);
    const loaded = loadCachedAdvisoryPayload(cacheDir, 60_000);

    expect(loaded).toEqual(payload);
  });

  it("uses a stable cache file path", () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "codegate-advisory-cache-path-"));

    expect(resolveGithubMetadataCachePath(cacheDir)).toBe(join(cacheDir, "gha-advisories.json"));
  });

  it("returns null when cache is expired", () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "codegate-advisory-cache-expired-"));
    const payload = {
      generatedAt: 1,
      advisories: {
        "actions/checkout": ["v3"],
      },
    };

    saveCachedAdvisoryPayload(cacheDir, payload);
    const loaded = loadCachedAdvisoryPayload(cacheDir, 1);

    expect(loaded).toBeNull();
  });

  it("keeps legacy cache payloads readable", () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "codegate-advisory-cache-legacy-"));
    const payload = {
      generatedAt: Date.now(),
      advisories: {
        "actions/checkout": ["v3"],
      },
    };
    const cachePath = resolveGithubMetadataCachePath(cacheDir);

    writeFileSync(cachePath, JSON.stringify(payload, null, 2), "utf8");
    const raw = JSON.parse(readFileSync(cachePath, "utf8")) as typeof payload;

    expect(loadCachedAdvisoryPayload(cacheDir, 60_000)).toEqual(raw);
  });
});
