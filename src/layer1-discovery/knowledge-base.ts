import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type ErrorObject } from "ajv";

export interface KnowledgeBasePathEntry {
  path: string;
  scope: "project" | "user";
  format: "jsonc" | "json" | "toml" | "yaml" | "dotenv" | "text" | "markdown";
  risk_surface: string[];
  fields_of_interest?: Record<string, string>;
}

export interface KnowledgeBaseSkillEntry {
  path: string;
  scope: "project" | "user";
  type: string;
  risk_surface: string[];
}

export interface KnowledgeBaseExtensionMechanism {
  type: string;
  install_pattern: string;
  risk: string;
  fetchable: boolean;
}

export interface KnowledgeBaseEntry {
  tool: string;
  version_range: string;
  config_paths: KnowledgeBasePathEntry[];
  skill_paths?: KnowledgeBaseSkillEntry[];
  extension_mechanisms?: KnowledgeBaseExtensionMechanism[];
}

interface KnowledgeBaseSchema {
  schema_version?: string;
}

export interface KnowledgeBaseLoadResult {
  schemaVersion: string;
  entries: KnowledgeBaseEntry[];
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

const defaultKnowledgeBaseDir = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../knowledge-base",
);
const schemaPath = join(defaultKnowledgeBaseDir, "schema.json");
const require = createRequire(import.meta.url);
const Ajv = require("ajv") as typeof import("ajv").default;

function loadSchema(path = schemaPath): KnowledgeBaseSchema {
  const raw = readFileSync(path, "utf8");
  return JSON.parse(raw) as KnowledgeBaseSchema;
}

function createValidator(path = schemaPath) {
  const ajv = new Ajv({ allErrors: true, strict: false });
  const schema = JSON.parse(readFileSync(path, "utf8")) as object;
  return ajv.compile<KnowledgeBaseEntry>(schema);
}

function toErrors(errors: ErrorObject[] | null | undefined): string[] {
  if (!errors) {
    return [];
  }
  return errors.map((error) => {
    const location = error.instancePath === "" ? "<root>" : error.instancePath;
    return `${location}: ${error.message ?? "validation error"}`;
  });
}

export function validateKnowledgeBaseEntry(
  candidate: unknown,
  path = schemaPath,
): ValidationResult {
  const validator = createValidator(path);
  const valid = validator(candidate);
  return {
    valid,
    errors: toErrors(validator.errors),
  };
}

export function loadKnowledgeBase(baseDir = defaultKnowledgeBaseDir): KnowledgeBaseLoadResult {
  const schema = loadSchema(join(baseDir, "schema.json"));
  const validator = createValidator(join(baseDir, "schema.json"));

  const entryFiles = readdirSync(baseDir)
    .filter((file) => extname(file) === ".json")
    .filter((file) => file !== "schema.json")
    .sort();

  const entries: KnowledgeBaseEntry[] = [];

  for (const entryFile of entryFiles) {
    const fullPath = join(baseDir, entryFile);
    const raw = readFileSync(fullPath, "utf8");
    const parsed = JSON.parse(raw) as unknown;

    const valid = validator(parsed);
    if (!valid) {
      const reasons = toErrors(validator.errors).join("; ");
      throw new Error(`Invalid knowledge base entry: ${entryFile} (${reasons})`);
    }
    entries.push(parsed as KnowledgeBaseEntry);
  }

  return {
    schemaVersion: schema.schema_version ?? "unknown",
    entries,
  };
}
