import { homedir } from "node:os";
import { join } from "node:path";
import type { RuntimeMode } from "../../config.js";
import bundledAdvisories from "../advisories/gha-known-vulnerable-actions.json" with { type: "json" };
import {
  loadCachedAdvisoryPayload,
  saveCachedAdvisoryPayload,
  type AdvisoryPayload,
} from "./cache.js";

function normalizeAdvisoryMap(value: Record<string, string[]>): Record<string, string[]> {
  const normalized: Record<string, string[]> = {};
  for (const [action, versions] of Object.entries(value)) {
    normalized[action.toLowerCase()] = versions.map((version) => version.toLowerCase());
  }
  return normalized;
}

export interface GithubMetadataClientOptions {
  runtimeMode?: RuntimeMode;
  cacheDir?: string;
  cacheMaxAgeMs?: number;
  now?: number;
}

export interface GithubMetadataClient {
  runtimeMode: RuntimeMode;
  cacheDir: string;
  cacheMaxAgeMs: number;
  isOnlineEnabled(): boolean;
  loadKnownVulnerableActions(bundle: Record<string, string[]>): AdvisoryPayload;
}

export function createGithubMetadataClient(
  options: GithubMetadataClientOptions = {},
): GithubMetadataClient {
  const runtimeMode = options.runtimeMode ?? "offline";
  const cacheDir = options.cacheDir ?? join(homedir(), ".codegate", "cache");
  const cacheMaxAgeMs = options.cacheMaxAgeMs ?? 24 * 60 * 60 * 1000;
  const now = options.now ?? Date.now();

  return {
    runtimeMode,
    cacheDir,
    cacheMaxAgeMs,
    isOnlineEnabled() {
      return runtimeMode === "online";
    },
    loadKnownVulnerableActions(bundle: Record<string, string[]>): AdvisoryPayload {
      const payload: AdvisoryPayload = {
        generatedAt: now,
        advisories: normalizeAdvisoryMap(bundle),
      };

      if (!runtimeMode || runtimeMode !== "online") {
        return payload;
      }

      const cached = loadCachedAdvisoryPayload(cacheDir, cacheMaxAgeMs, now);
      if (cached) {
        return cached;
      }

      saveCachedAdvisoryPayload(cacheDir, payload);
      return payload;
    },
  };
}

export function loadBundledGithubAdvisories(
  options: GithubMetadataClientOptions = {},
): AdvisoryPayload {
  return createGithubMetadataClient(options).loadKnownVulnerableActions(
    bundledAdvisories as Record<string, string[]>,
  );
}
