import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  KNOWN_BAD_INDICATOR_KEYS,
  type KnownBadIndicatorKey,
  type KnownBadIndicators,
} from "./content-bundle.js";
import { loadActiveContentBundle } from "./content-store.js";

export interface KnownBadDeps {
  homeDir?: () => string;
}

const LOCAL_INDICATORS_FILE = "known-bad.json";
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/u;
const SHA256_PREFIX = "sha256:";

/**
 * Indicators normalized for matching: hashes and package names lowercased,
 * fingerprints carrying the `sha256:` prefix used by finding fingerprints.
 */
export interface ResolvedKnownBadIndicators {
  fileSha256: ReadonlySet<string>;
  packageNames: ReadonlySet<string>;
  urlPatterns: readonly string[];
  findingFingerprints: ReadonlySet<string>;
}

export function hasKnownBadIndicators(indicators: ResolvedKnownBadIndicators): boolean {
  return (
    indicators.fileSha256.size > 0 ||
    indicators.packageNames.size > 0 ||
    indicators.urlPatterns.length > 0 ||
    indicators.findingFingerprints.size > 0
  );
}

/** Accepts `sha256:<hex>` or bare hex; returns bare lowercase hex or null. */
export function normalizeSha256Indicator(value: string): string | null {
  const trimmed = value.trim().toLowerCase();
  const bare = trimmed.startsWith(SHA256_PREFIX) ? trimmed.slice(SHA256_PREFIX.length) : trimmed;
  return SHA256_HEX_PATTERN.test(bare) ? bare : null;
}

/** Finding fingerprints are stored and compared with the `sha256:` prefix. */
export function normalizeFingerprintIndicator(value: string): string | null {
  const bare = normalizeSha256Indicator(value);
  return bare === null ? null : `${SHA256_PREFIX}${bare}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Keep only well-formed string lists; anything else degrades to empty. */
function sanitizeIndicators(value: unknown): KnownBadIndicators {
  if (!isRecord(value)) {
    return {};
  }
  const sanitized: KnownBadIndicators = {};
  for (const key of KNOWN_BAD_INDICATOR_KEYS) {
    const list = value[key];
    if (Array.isArray(list)) {
      sanitized[key] = list.filter(
        (entry): entry is string => typeof entry === "string" && entry.trim().length > 0,
      );
    }
  }
  return sanitized;
}

function loadLocalIndicators(deps: KnownBadDeps): KnownBadIndicators {
  const home = deps.homeDir ? deps.homeDir() : homedir();
  try {
    const raw = readFileSync(join(home, ".codegate", LOCAL_INDICATORS_FILE), "utf8");
    return sanitizeIndicators(JSON.parse(raw) as unknown);
  } catch {
    return {};
  }
}

function indicatorList(
  sources: readonly KnownBadIndicators[],
  key: KnownBadIndicatorKey,
): string[] {
  return sources.flatMap((source) => source[key] ?? []);
}

function resolveIndicators(sources: readonly KnownBadIndicators[]): ResolvedKnownBadIndicators {
  const fileSha256 = new Set<string>();
  for (const entry of indicatorList(sources, "file_sha256")) {
    const normalized = normalizeSha256Indicator(entry);
    if (normalized) {
      fileSha256.add(normalized);
    }
  }

  const packageNames = new Set(
    indicatorList(sources, "package_names").map((entry) => entry.trim().toLowerCase()),
  );

  const urlPatterns = Array.from(
    new Set(indicatorList(sources, "url_patterns").map((entry) => entry.trim().toLowerCase())),
  );

  const findingFingerprints = new Set<string>();
  for (const entry of indicatorList(sources, "finding_fingerprints")) {
    const normalized = normalizeFingerprintIndicator(entry);
    if (normalized) {
      findingFingerprints.add(normalized);
    }
  }

  return { fileSha256, packageNames, urlPatterns, findingFingerprints };
}

let cache: { key: string; indicators: ResolvedKnownBadIndicators } | null = null;

export function resetKnownBadIndicatorsCache(): void {
  cache = null;
}

/**
 * Known-bad indicators merged from the verified content feed and the local
 * `~/.codegate/known-bad.json`. The local file is user-controlled (same trust
 * as the global config) and exists so indicators work before the feed is
 * live. Never throws: indicator problems must not break scanning.
 */
export function loadKnownBadIndicators(deps: KnownBadDeps = {}): ResolvedKnownBadIndicators {
  const home = deps.homeDir ? deps.homeDir() : homedir();
  if (cache && cache.key === home) {
    return cache.indicators;
  }

  let feedIndicators: KnownBadIndicators;
  try {
    feedIndicators = sanitizeIndicators(loadActiveContentBundle()?.known_bad);
  } catch {
    feedIndicators = {};
  }

  const indicators = resolveIndicators([feedIndicators, loadLocalIndicators(deps)]);
  cache = { key: home, indicators };
  return indicators;
}
