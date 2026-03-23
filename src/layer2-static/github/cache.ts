import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface AdvisoryPayload {
  generatedAt: number;
  advisories: Record<string, string[]>;
}

export const GITHUB_METADATA_CACHE_FILE = "gha-advisories.json";

export function resolveGithubMetadataCachePath(cacheDir: string): string {
  return join(cacheDir, GITHUB_METADATA_CACHE_FILE);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAdvisoryPayload(value: unknown): value is AdvisoryPayload {
  if (!isRecord(value) || typeof value.generatedAt !== "number") {
    return false;
  }
  if (!isRecord(value.advisories)) {
    return false;
  }

  return Object.values(value.advisories).every(
    (entry) => Array.isArray(entry) && entry.every((item) => typeof item === "string"),
  );
}

export function loadCachedAdvisoryPayload(
  cacheDir: string,
  maxAgeMs: number,
  now = Date.now(),
): AdvisoryPayload | null {
  const path = resolveGithubMetadataCachePath(cacheDir);
  if (!existsSync(path)) {
    return null;
  }

  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!isAdvisoryPayload(parsed)) {
      return null;
    }
    if (now - parsed.generatedAt > maxAgeMs) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function saveCachedAdvisoryPayload(cacheDir: string, payload: AdvisoryPayload): void {
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(resolveGithubMetadataCachePath(cacheDir), JSON.stringify(payload, null, 2), "utf8");
}
