import { createHash } from "node:crypto";
import type { Finding } from "../types/finding.js";

function normalizeLocation(location: Finding["location"]): {
  field?: string;
  line?: number;
  column?: number;
} {
  const normalized: {
    field?: string;
    line?: number;
    column?: number;
  } = {};

  if (typeof location.field === "string" && location.field.length > 0) {
    normalized.field = location.field;
  }
  if (typeof location.line === "number") {
    normalized.line = location.line;
  }
  if (typeof location.column === "number") {
    normalized.column = location.column;
  }

  return normalized;
}

function normalizeSourceConfig(sourceConfig: Finding["source_config"]): {
  file_path: string;
  field?: string;
} | null {
  if (!sourceConfig) {
    return null;
  }

  const normalized: {
    file_path: string;
    field?: string;
  } = {
    file_path: sourceConfig.file_path,
  };

  if (typeof sourceConfig.field === "string" && sourceConfig.field.length > 0) {
    normalized.field = sourceConfig.field;
  }

  return normalized;
}

function buildFingerprintPayload(finding: Finding): Record<string, unknown> {
  return {
    rule_id: finding.rule_id,
    category: finding.category,
    layer: finding.layer,
    file_path: finding.file_path,
    location: normalizeLocation(finding.location),
    source_config: normalizeSourceConfig(finding.source_config),
    cwe: finding.cwe,
  };
}

export function buildFindingFingerprint(finding: Finding): string {
  const payload = JSON.stringify(buildFingerprintPayload(finding));
  return `sha256:${createHash("sha256").update(payload).digest("hex")}`;
}

export function withFindingFingerprint<T extends Finding>(finding: T): T & { fingerprint: string } {
  return {
    ...finding,
    fingerprint: buildFindingFingerprint(finding),
  };
}
