import type { Finding } from "../types/finding.js";

export interface SuppressionRule {
  rule_id?: string;
  file_path?: string;
  location?: string;
  severity?: Finding["severity"];
  category?: Finding["category"];
  cwe?: string;
  fingerprint?: string;
}

export interface RulePolicyConfig {
  disable?: boolean;
  ignore?: readonly string[];
  config?: Record<string, unknown>;
}

export type RulePolicyMap = Record<string, RulePolicyConfig>;

export interface SuppressionPolicy {
  suppress_findings?: readonly string[];
  suppression_rules?: readonly SuppressionRule[];
  rule_policies?: RulePolicyMap;
}

function normalizeString(value: string | undefined): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegExp(glob: string): RegExp {
  const pattern = normalizeString(glob)?.replaceAll("\\", "/");
  if (!pattern) {
    return /^$/;
  }

  let regex = "^";
  for (let index = 0; index < pattern.length; index++) {
    const char = pattern[index];

    if (char === "*") {
      if (pattern[index + 1] === "*") {
        regex += ".*";
        index++;
      } else {
        regex += "[^/]*";
      }
      continue;
    }

    if (char === "?") {
      regex += "[^/]";
      continue;
    }

    regex += escapeRegExp(char);
  }

  regex += "$";
  return new RegExp(regex);
}

function matchesGlob(value: string, glob: string): boolean {
  return globToRegExp(glob).test(value.replaceAll("\\", "/"));
}

interface SuppressionLocation {
  filePath: string;
  line?: number;
  column?: number;
}

function parseSuppressionLocation(value: string): SuppressionLocation | null {
  const trimmed = normalizeString(value);
  if (!trimmed) {
    return null;
  }

  const pieces = trimmed.split(":");
  if (pieces.length === 0 || pieces.length > 3) {
    return null;
  }

  const [filePath, lineRaw, columnRaw] = pieces;
  if (!filePath) {
    return null;
  }

  const line = lineRaw !== undefined ? Number.parseInt(lineRaw, 10) : undefined;
  const column = columnRaw !== undefined ? Number.parseInt(columnRaw, 10) : undefined;

  if (lineRaw !== undefined && (!Number.isFinite(line) || (line ?? 0) < 1)) {
    return null;
  }
  if (columnRaw !== undefined && (!Number.isFinite(column) || (column ?? 0) < 1)) {
    return null;
  }

  return {
    filePath: filePath.replaceAll("\\", "/"),
    line,
    column,
  };
}

function matchesSuppressionRule(finding: Finding, rule: SuppressionRule): boolean {
  const ruleId = normalizeString(rule.rule_id);
  if (ruleId && finding.rule_id !== ruleId) {
    return false;
  }

  const filePath = normalizeString(rule.file_path);
  if (filePath && !matchesGlob(finding.file_path, filePath)) {
    return false;
  }

  const location = parseSuppressionLocation(rule.location ?? "");
  if (location) {
    const normalizedFindingPath = finding.file_path.replaceAll("\\", "/");
    if (normalizedFindingPath !== location.filePath) {
      return false;
    }
    if (
      typeof location.line === "number" &&
      (typeof finding.location.line !== "number" || finding.location.line !== location.line)
    ) {
      return false;
    }
    if (
      typeof location.column === "number" &&
      (typeof finding.location.column !== "number" || finding.location.column !== location.column)
    ) {
      return false;
    }
  }

  const severity = rule.severity;
  if (severity && finding.severity !== severity) {
    return false;
  }

  const category = normalizeString(rule.category);
  if (category && finding.category !== category) {
    return false;
  }

  const cwe = normalizeString(rule.cwe);
  if (cwe && finding.cwe !== cwe) {
    return false;
  }

  const fingerprint = normalizeString(rule.fingerprint);
  if (fingerprint && finding.fingerprint !== fingerprint) {
    return false;
  }

  return true;
}

function matchesRulePolicyIgnore(finding: Finding, location: string): boolean {
  const parsed = parseSuppressionLocation(location);
  if (!parsed) {
    return false;
  }

  const normalizedFindingPath = finding.file_path.replaceAll("\\", "/");
  if (normalizedFindingPath !== parsed.filePath) {
    return false;
  }

  if (
    typeof parsed.line === "number" &&
    (typeof finding.location.line !== "number" || finding.location.line !== parsed.line)
  ) {
    return false;
  }

  if (
    typeof parsed.column === "number" &&
    (typeof finding.location.column !== "number" || finding.location.column !== parsed.column)
  ) {
    return false;
  }

  return true;
}

export function applySuppressionPolicy<T extends Finding>(
  findings: T[],
  policy: SuppressionPolicy,
): T[] {
  const legacySuppressions = new Set(
    (policy.suppress_findings ?? [])
      .map((findingId) => normalizeString(findingId))
      .filter((findingId): findingId is string => findingId !== undefined),
  );
  const rules = policy.suppression_rules ?? [];
  const rulePolicies = policy.rule_policies ?? {};

  return findings.map((finding) => {
    const ruleMatch = rules.some((rule) => matchesSuppressionRule(finding, rule));
    const legacyMatch = legacySuppressions.has(finding.finding_id);
    const rulePolicy = rulePolicies[finding.rule_id];
    const ruleDisabled = rulePolicy?.disable === true;
    const ruleIgnoreMatch =
      rulePolicy?.ignore?.some((location) => matchesRulePolicyIgnore(finding, location)) ?? false;

    return {
      ...finding,
      suppressed: finding.suppressed || legacyMatch || ruleMatch || ruleDisabled || ruleIgnoreMatch,
    };
  });
}
