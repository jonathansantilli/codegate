import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { KnowledgeBaseEntry } from "../layer1-discovery/knowledge-base.js";
import type { OverridePhrase } from "../layer2-static/text/override-phrases.js";

export const CONTENT_BUNDLE_SCHEMA_VERSION = "1";

export const KNOWN_BAD_INDICATOR_KEYS = [
  "file_sha256",
  "package_names",
  "url_patterns",
  "finding_fingerprints",
] as const;
export type KnownBadIndicatorKey = (typeof KNOWN_BAD_INDICATOR_KEYS)[number];

export type KnownBadIndicators = Partial<Record<KnownBadIndicatorKey, string[]>>;

/**
 * What a content version may contain, given it names a directory on disk.
 *
 * Deliberately an allowlist of the characters a version could plausibly need
 * — the feed publishes `YYYY.MM.DD` and `YYYY.MM.DD.N` today — rather than a
 * pattern matching that exact shape, so a future `-rc1` does not break
 * updates. What it cannot express is a path: no slash, no backslash, no NUL,
 * no leading dot, and `..` is rejected separately.
 */
export const CONTENT_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface ContentBundle {
  schema_version: string;
  content_version: string;
  released_at: string;
  kb_schema_version?: string;
  kb_entries?: KnowledgeBaseEntry[];
  rules?: unknown[];
  override_phrases?: OverridePhrase[];
  popular_packages?: { npm?: string[]; pypi?: string[] };
  known_bad?: KnownBadIndicators;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

/**
 * Verify the detached Ed25519 signature over the exact bundle bytes.
 * Verification always happens BEFORE parsing untrusted bytes.
 */
export function verifyBundleSignature(
  bundleBytes: Buffer,
  signatureBase64: string,
  publicKeyPem: string,
): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    const signature = Buffer.from(signatureBase64.trim(), "base64");
    return cryptoVerify(null, bundleBytes, key, signature);
  } catch {
    return false;
  }
}

/** Structural validation of a verified bundle. Throws with a clear reason. */
export function parseContentBundle(bundleBytes: Buffer): ContentBundle {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bundleBytes.toString("utf8")) as unknown;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Content bundle is not valid JSON: ${reason}`, { cause: error });
  }

  if (!isRecord(parsed)) {
    throw new Error("Content bundle must be a JSON object");
  }
  if (parsed.schema_version !== CONTENT_BUNDLE_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported content bundle schema_version: ${String(parsed.schema_version)} ` +
        `(this build supports ${CONTENT_BUNDLE_SCHEMA_VERSION})`,
    );
  }
  if (typeof parsed.content_version !== "string" || parsed.content_version.length === 0) {
    throw new Error("Content bundle is missing content_version");
  }
  // The version names a directory on disk, so it is constrained here rather
  // than trusted at the point it is joined to a path. A bundle is signature
  // verified before it is stored, so reaching that join with a hostile value
  // already means the signing key is compromised — but a single control is
  // not a design, and "../.." in a version string should never be one
  // mistake away from writing outside the content root.
  if (
    !CONTENT_VERSION_PATTERN.test(parsed.content_version) ||
    parsed.content_version.includes("..")
  ) {
    throw new Error(`Content bundle has an unusable content_version: ${parsed.content_version}`);
  }
  if (typeof parsed.released_at !== "string" || Number.isNaN(Date.parse(parsed.released_at))) {
    throw new Error("Content bundle is missing a valid released_at timestamp");
  }
  if (parsed.kb_entries !== undefined && !Array.isArray(parsed.kb_entries)) {
    throw new Error("Content bundle kb_entries must be an array");
  }
  if (parsed.rules !== undefined && !Array.isArray(parsed.rules)) {
    throw new Error("Content bundle rules must be an array");
  }
  if (parsed.override_phrases !== undefined && !Array.isArray(parsed.override_phrases)) {
    throw new Error("Content bundle override_phrases must be an array");
  }
  if (parsed.known_bad !== undefined) {
    if (!isRecord(parsed.known_bad)) {
      throw new Error("Content bundle known_bad must be an object");
    }
    for (const key of KNOWN_BAD_INDICATOR_KEYS) {
      const list = (parsed.known_bad as Record<string, unknown>)[key];
      if (list !== undefined && !isStringArray(list)) {
        throw new Error(`Content bundle known_bad.${key} must be an array of strings`);
      }
    }
  }

  return parsed as unknown as ContentBundle;
}
