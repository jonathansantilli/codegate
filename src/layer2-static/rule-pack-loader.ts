import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type ErrorObject } from "ajv";
import type { DetectionRule } from "./rule-engine.js";

export interface RulePackLoaderOptions {
  baseDir?: string;
  rule_pack_paths?: string[];
  allowed_rules?: string[];
  skip_rules?: string[];
}

interface LoadRulePackOptions {
  baseDir: string;
  rulePackPaths: string[];
  allowedRules: string[];
  skipRules: string[];
}

const defaultRulesDir = resolve(dirname(fileURLToPath(import.meta.url)), "rules");
const require = createRequire(import.meta.url);
const Ajv = require("ajv") as typeof import("ajv").default;

const RULE_SCHEMA = {
  type: "object",
  additionalProperties: true,
  required: [
    "id",
    "severity",
    "category",
    "description",
    "tool",
    "file_pattern",
    "query_type",
    "query",
    "condition",
    "owasp",
    "cwe",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    severity: { type: "string", minLength: 1 },
    category: { type: "string", minLength: 1 },
    description: { type: "string", minLength: 1 },
    tool: { type: "string", minLength: 1 },
    file_pattern: { type: "string", minLength: 1 },
    query_type: {
      type: "string",
      enum: ["json_path", "toml_path", "env_key", "text_pattern"],
    },
    query: { type: "string" },
    condition: {
      type: "string",
      enum: [
        "equals_true",
        "equals_false",
        "exists",
        "not_empty",
        "matches_regex",
        "not_in_allowlist",
        "regex_match",
        "contains",
        "line_length_exceeds",
      ],
    },
    cve: { type: "string" },
    owasp: {
      type: "array",
      items: { type: "string" },
    },
    cwe: { type: "string", minLength: 1 },
  },
} as const;

const ruleValidator = new Ajv({ allErrors: true, strict: false }).compile(RULE_SCHEMA);

function normalizeRuleIds(values: string[] | undefined): string[] {
  const seen = new Set<string>();
  const normalized: string[] = [];

  for (const value of values ?? []) {
    const trimmed = value.trim();
    if (trimmed.length === 0 || seen.has(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    normalized.push(trimmed);
  }

  return normalized;
}

function toErrorMessage(errors: ErrorObject[] | null | undefined): string {
  if (!errors || errors.length === 0) {
    return "validation error";
  }

  return errors
    .map((error) => {
      const location = error.instancePath === "" ? "<root>" : error.instancePath;
      return `${location}: ${error.message ?? "validation error"}`;
    })
    .join("; ");
}

function isPackDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function isPackFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function resolvePackPaths(path: string): string[] {
  const absolutePath = resolve(path);
  if (!existsSync(absolutePath)) {
    throw new Error(`Rule pack path does not exist: ${absolutePath}`);
  }

  if (isPackFile(absolutePath)) {
    return [absolutePath];
  }

  if (!isPackDirectory(absolutePath)) {
    throw new Error(`Rule pack path is not a file or directory: ${absolutePath}`);
  }

  return readdirSync(absolutePath)
    .filter((file) => extname(file) === ".json")
    .filter((file) => file !== "schema.json")
    .sort()
    .map((file) => join(absolutePath, file));
}

function loadRulesFromFile(path: string): DetectionRule[] {
  let parsed: unknown;

  try {
    parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse rule pack ${path}: ${reason}`, { cause: error });
  }

  if (!Array.isArray(parsed)) {
    throw new Error(`Invalid rule pack ${path}: expected a JSON array of rule objects`);
  }

  return parsed.map((candidate, index) => {
    if (!ruleValidator(candidate)) {
      const reasons = toErrorMessage(ruleValidator.errors);
      throw new Error(`Invalid rule pack ${path} [${index}]: ${reasons}`);
    }

    return candidate as DetectionRule;
  });
}

function collectRulesFromPaths(paths: string[]): DetectionRule[] {
  const collected: DetectionRule[] = [];

  for (const path of paths) {
    for (const packPath of resolvePackPaths(path)) {
      collected.push(...loadRulesFromFile(packPath));
    }
  }

  return collected;
}

function dedupeByRuleId(rules: DetectionRule[]): DetectionRule[] {
  const deduped = new Map<string, DetectionRule>();

  for (const rule of rules) {
    deduped.set(rule.id, rule);
  }

  return Array.from(deduped.values());
}

function filterRules(
  rules: DetectionRule[],
  allowedRules: string[],
  skipRules: string[],
): DetectionRule[] {
  const allowed = new Set(allowedRules);
  const skipped = new Set(skipRules);

  return rules.filter((rule) => {
    if (skipped.has(rule.id)) {
      return false;
    }
    if (allowed.size > 0 && !allowed.has(rule.id)) {
      return false;
    }
    return true;
  });
}

function normalizeOptions(arg?: string | RulePackLoaderOptions): LoadRulePackOptions {
  if (typeof arg === "string") {
    return {
      baseDir: arg,
      rulePackPaths: [],
      allowedRules: [],
      skipRules: [],
    };
  }

  const options = arg ?? {};
  return {
    baseDir: options.baseDir ?? defaultRulesDir,
    rulePackPaths: options.rule_pack_paths ?? [],
    allowedRules: normalizeRuleIds(options.allowed_rules),
    skipRules: normalizeRuleIds(options.skip_rules),
  };
}

export function loadRulePacks(): DetectionRule[];
export function loadRulePacks(baseDir: string): DetectionRule[];
export function loadRulePacks(options: RulePackLoaderOptions): DetectionRule[];
export function loadRulePacks(arg?: string | RulePackLoaderOptions): DetectionRule[] {
  const options = normalizeOptions(arg);
  const bundledRules = collectRulesFromPaths([options.baseDir]);
  const externalRules = collectRulesFromPaths(options.rulePackPaths);
  return filterRules(
    dedupeByRuleId([...bundledRules, ...externalRules]),
    options.allowedRules,
    options.skipRules,
  );
}
