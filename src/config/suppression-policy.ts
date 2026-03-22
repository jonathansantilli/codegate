import type { Finding } from "../types/finding.js";

export interface SuppressionRule {
  rule_id?: string;
  file_path?: string;
  severity?: Finding["severity"];
  category?: Finding["category"];
  cwe?: string;
  fingerprint?: string;
}

export interface SuppressionPolicy {
  suppress_findings?: readonly string[];
  suppression_rules?: readonly SuppressionRule[];
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

function matchesSuppressionRule(finding: Finding, rule: SuppressionRule): boolean {
  const ruleId = normalizeString(rule.rule_id);
  if (ruleId && finding.rule_id !== ruleId) {
    return false;
  }

  const filePath = normalizeString(rule.file_path);
  if (filePath && !matchesGlob(finding.file_path, filePath)) {
    return false;
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

  return findings.map((finding) => {
    const ruleMatch = rules.some((rule) => matchesSuppressionRule(finding, rule));
    const legacyMatch = legacySuppressions.has(finding.finding_id);

    return {
      ...finding,
      suppressed: finding.suppressed || legacyMatch || ruleMatch,
    };
  });
}
