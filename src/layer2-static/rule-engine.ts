export type RuleQueryType = "json_path" | "toml_path" | "env_key" | "text_pattern";
export type RuleCondition =
  | "equals_true"
  | "equals_false"
  | "exists"
  | "not_empty"
  | "matches_regex"
  | "not_in_allowlist"
  | "regex_match"
  | "contains"
  | "line_length_exceeds";

export interface DetectionRule {
  id: string;
  severity: string;
  category: string;
  description: string;
  tool: string;
  file_pattern: string;
  query_type: RuleQueryType;
  query: string;
  condition: RuleCondition;
  cve?: string;
  owasp: string[];
  cwe: string;
}

export interface RuleEvaluationInput {
  filePath: string;
  format: string;
  parsed: unknown;
  textContent: string;
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

function wildcardToRegex(pattern: string): RegExp {
  const escaped = escapeRegex(pattern).replace(/\*/g, "[^/]*");
  return new RegExp(`^${escaped}$`);
}

function matchesFilePattern(pattern: string, filePath: string): boolean {
  return pattern
    .split("|")
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .some((part) => wildcardToRegex(part).test(filePath));
}

function getValuesByPath(root: unknown, segments: string[]): unknown[] {
  if (segments.length === 0) {
    return [root];
  }

  const [head, ...tail] = segments;

  if (head === "*") {
    if (root === null || typeof root !== "object") {
      return [];
    }
    const values = Array.isArray(root) ? root : Object.values(root as Record<string, unknown>);
    return values.flatMap((value) => getValuesByPath(value, tail));
  }

  if (root === null || typeof root !== "object") {
    return [];
  }

  const record = root as Record<string, unknown>;
  if (!(head in record)) {
    return [];
  }
  return getValuesByPath(record[head], tail);
}

function resolveJsonPath(parsed: unknown, query: string): unknown[] {
  const normalized = query.startsWith("$.") ? query.slice(2) : query.replace(/^\$/, "");
  if (!normalized) {
    return [parsed];
  }
  return getValuesByPath(parsed, normalized.split("."));
}

function resolveTomlPath(parsed: unknown, query: string): unknown[] {
  return getValuesByPath(parsed, query.split("."));
}

function resolveEnvKeys(parsed: unknown, query: string): unknown[] {
  if (!parsed || typeof parsed !== "object") {
    return [];
  }
  const record = parsed as Record<string, unknown>;
  const keys = query.split("|").map((token) => token.trim());
  return keys.filter((key) => key in record).map((key) => record[key]);
}

function evaluateCondition(values: unknown[], condition: RuleCondition, query: string): boolean {
  const first = values[0];
  switch (condition) {
    case "equals_true":
      return first === true;
    case "equals_false":
      return first === false;
    case "exists":
      return values.length > 0;
    case "not_empty":
      if (values.length === 0) {
        return false;
      }
      if (typeof first === "string") {
        return first.trim().length > 0;
      }
      if (Array.isArray(first)) {
        return first.length > 0;
      }
      if (first && typeof first === "object") {
        return Object.keys(first).length > 0;
      }
      return first !== null && first !== undefined;
    case "matches_regex": {
      const regex = new RegExp(query);
      return values.some((value) => regex.test(String(value)));
    }
    case "not_in_allowlist": {
      const allowlist = query.split("|").map((token) => token.trim());
      return values.some((value) => !allowlist.includes(String(value)));
    }
    default:
      return false;
  }
}

function evaluateTextCondition(content: string, condition: RuleCondition, query: string): boolean {
  switch (condition) {
    case "regex_match": {
      const regex = new RegExp(query, "u");
      return regex.test(content);
    }
    case "contains":
      return content.includes(query);
    case "line_length_exceeds": {
      const threshold = Number.parseInt(query, 10);
      if (Number.isNaN(threshold)) {
        return false;
      }
      return content.split(/\r?\n/u).some((line) => line.length > threshold);
    }
    default:
      return false;
  }
}

export function evaluateRule(rule: DetectionRule, input: RuleEvaluationInput): boolean {
  if (!matchesFilePattern(rule.file_pattern, input.filePath)) {
    return false;
  }

  if (rule.query_type === "text_pattern") {
    return evaluateTextCondition(input.textContent, rule.condition, rule.query);
  }

  if (rule.query_type === "json_path") {
    return evaluateCondition(resolveJsonPath(input.parsed, rule.query), rule.condition, rule.query);
  }

  if (rule.query_type === "toml_path") {
    return evaluateCondition(resolveTomlPath(input.parsed, rule.query), rule.condition, rule.query);
  }

  if (rule.query_type === "env_key") {
    return evaluateCondition(resolveEnvKeys(input.parsed, rule.query), rule.condition, rule.query);
  }

  return false;
}

export { loadRulePacks } from "./rule-pack-loader.js";
