import { existsSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

import {
  loadKnowledgeBase,
  type KnowledgeBaseEntry,
  type KnowledgeBasePathEntry,
  type KnowledgeBaseSkillEntry,
} from "../layer1-discovery/knowledge-base.js";

/** One resolved artifact the scanner knows about. */
export interface InventoryItem {
  tool: string;
  kind: "config" | "skill";
  /** Only set for skill entries; mirrors KB `skill_paths[].type`. */
  type?: string;
  scope: "user" | "project";
  /** Pattern as declared in the KB (relative, may contain wildcards). */
  pattern: string;
  /** Absolute resolved filesystem path (concrete, not the pattern). */
  path: string;
  /** True if the filesystem shows the path exists. */
  exists: boolean;
  risk_surface: string[];
  /**
   * How the file is written: markdown and text are prose, the rest hold
   * structured configuration. Declared by the knowledge base for config
   * entries; derived from the resolved path for skills, which the knowledge
   * base does not tag. Absent when neither is available, which a consumer
   * should read as "unknown" rather than as "safe".
   */
  format?: string;
  /** Only populated for config entries that declare them. */
  fields_of_interest?: Record<string, string>;
  /** Resolution root used (e.g., the home dir or a workspace root). */
  resolved_against: string;
}

export interface InventorySummary {
  kb_version: string;
  /** Known tools (from KB file names) with their version ranges. */
  tools: Array<{ name: string; version_range: string }>;
  items: InventoryItem[];
}

export interface InventoryOptions {
  scope: "user" | "project" | "all";
  kind: "skills" | "configs" | "all";
  onlyExisting: boolean;
  /** Roots for project-scope resolution. Empty if project scope is skipped. */
  workspaces: string[];
  homeDir: string;
  /** Optional injection for tests. */
  kbBaseDir?: string;
}

const MAX_WILDCARD_DEPTH = 8;
const MAX_WILDCARD_MATCHES = 2000;

export function runInventory(options: InventoryOptions): InventorySummary {
  const kb = loadKnowledgeBase(options.kbBaseDir);
  const includeConfigs = options.kind === "all" || options.kind === "configs";
  const includeSkills = options.kind === "all" || options.kind === "skills";

  const rawItems: InventoryItem[] = [];

  for (const entry of kb.entries) {
    if (includeConfigs) {
      for (const cp of entry.config_paths) {
        rawItems.push(...resolveConfigEntry(entry.tool, cp, options));
      }
    }
    if (includeSkills) {
      for (const sp of entry.skill_paths ?? []) {
        rawItems.push(...resolveSkillEntry(entry.tool, sp, options));
      }
    }
  }

  const items = options.onlyExisting ? rawItems.filter((item) => item.exists) : rawItems;

  // Stable ordering: by tool, then kind, then scope, then path.
  items.sort((a, b) => {
    if (a.tool !== b.tool) return a.tool.localeCompare(b.tool);
    if (a.kind !== b.kind) return a.kind.localeCompare(b.kind);
    if (a.scope !== b.scope) return a.scope.localeCompare(b.scope);
    return a.path.localeCompare(b.path);
  });

  return {
    kb_version: kb.schemaVersion,
    tools: kb.entries
      .map((entry: KnowledgeBaseEntry) => ({
        name: entry.tool,
        version_range: entry.version_range,
      }))
      .sort((a, b) => a.name.localeCompare(b.name)),
    items,
  };
}

function resolveConfigEntry(
  tool: string,
  cp: KnowledgeBasePathEntry,
  options: InventoryOptions,
): InventoryItem[] {
  if (!scopeIncluded(cp.scope, options.scope)) return [];
  const roots = rootsFor(cp.scope, options);
  const items: InventoryItem[] = [];
  for (const root of roots) {
    items.push(
      ...resolvePattern({
        tool,
        kind: "config",
        scope: cp.scope,
        pattern: cp.path,
        root,
        riskSurface: cp.risk_surface,
        format: cp.format,
        fieldsOfInterest: cp.fields_of_interest,
      }),
    );
  }
  return items;
}

function resolveSkillEntry(
  tool: string,
  sp: KnowledgeBaseSkillEntry,
  options: InventoryOptions,
): InventoryItem[] {
  if (!scopeIncluded(sp.scope, options.scope)) return [];
  const roots = rootsFor(sp.scope, options);
  const items: InventoryItem[] = [];
  for (const root of roots) {
    items.push(
      ...resolvePattern({
        tool,
        kind: "skill",
        type: sp.type,
        scope: sp.scope,
        pattern: sp.path,
        root,
        riskSurface: sp.risk_surface,
      }),
    );
  }
  return items;
}

function scopeIncluded(
  entryScope: "user" | "project",
  optionScope: InventoryOptions["scope"],
): boolean {
  if (optionScope === "all") return true;
  return entryScope === optionScope;
}

function rootsFor(entryScope: "user" | "project", options: InventoryOptions): string[] {
  if (entryScope === "user") return [options.homeDir];
  if (options.workspaces.length === 0) return [];
  return options.workspaces;
}

interface ResolvePatternInput {
  tool: string;
  kind: "config" | "skill";
  type?: string;
  scope: "user" | "project";
  pattern: string;
  root: string;
  riskSurface: string[];
  format?: string;
  fieldsOfInterest?: Record<string, string>;
}

function resolvePattern(input: ResolvePatternInput): InventoryItem[] {
  const normalized = normalizePattern(input.pattern);
  const hasWildcard = /[*?]/.test(normalized);

  if (!hasWildcard) {
    const absolute = resolve(input.root, normalized);
    return [makeItem(input, absolute, existsSync(absolute))];
  }

  const matches = expandWildcard(input.root, normalized);
  return matches.map((absolute) => makeItem(input, absolute, true));
}

/**
 * Format for an entry the knowledge base does not declare one for.
 *
 * Only skill entries lack it, and their resolved paths are concrete by the
 * time this runs, so the extension is a reliable answer. Anything unrecognised
 * stays undefined rather than being guessed at: a consumer deciding whether a
 * file is prose should be told "unknown", not told "text" on no evidence.
 */
function formatFromPath(absolute: string): string | undefined {
  const match = absolute.toLowerCase().match(/\.[a-z0-9]+$/u);
  switch (match?.[0]) {
    case ".md":
    case ".markdown":
    case ".mdc":
    case ".clinerules":
    case ".cursorrules":
    case ".roorules":
    case ".windsurfrules":
      return "markdown";
    case ".txt":
      return "text";
    case ".json":
      return "json";
    case ".jsonc":
    case ".json5":
      return "jsonc";
    case ".toml":
      return "toml";
    case ".yaml":
    case ".yml":
      return "yaml";
    case ".env":
      return "dotenv";
    case ".xml":
      return "xml";
    default:
      return;
  }
}

function makeItem(input: ResolvePatternInput, absolute: string, exists: boolean): InventoryItem {
  return {
    tool: input.tool,
    kind: input.kind,
    type: input.type,
    scope: input.scope,
    pattern: input.pattern,
    path: absolute,
    exists,
    risk_surface: input.riskSurface,
    format: input.format ?? formatFromPath(absolute),
    fields_of_interest: input.fieldsOfInterest,
    resolved_against: input.root,
  };
}

function normalizePattern(pattern: string): string {
  return pattern.replace(/^~\//, "").replace(/^\/+/, "");
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.*]/g, "\\$&");
}

function wildcardToRegex(pattern: string): RegExp {
  let escaped = escapeRegex(pattern);
  escaped = escaped.replace(/\\\*\\\*\//g, "(?:[^/]+/)*");
  escaped = escaped.replace(/\\\*\\\*/g, ".*");
  escaped = escaped.replace(/\\\*/g, "[^/]*");
  escaped = escaped.replace(/\\\?/g, "[^/]");
  return new RegExp(`^${escaped}$`);
}

function fixedPrefix(pattern: string): string {
  const firstStar = pattern.indexOf("*");
  const firstQuestion = pattern.indexOf("?");
  const firstWildcard =
    firstStar === -1
      ? firstQuestion
      : firstQuestion === -1
        ? firstStar
        : Math.min(firstStar, firstQuestion);
  if (firstWildcard === -1) return pattern;
  const prefix = pattern.slice(0, firstWildcard);
  const lastSlash = prefix.lastIndexOf("/");
  return lastSlash === -1 ? "" : prefix.slice(0, lastSlash);
}

function expandWildcard(root: string, pattern: string): string[] {
  const matchRegex = wildcardToRegex(pattern);
  const prefix = fixedPrefix(pattern);
  const baseDir = prefix ? resolve(root, prefix) : resolve(root);
  if (!existsSync(baseDir)) return [];
  try {
    if (!statSync(baseDir).isDirectory()) return [];
  } catch {
    return [];
  }

  const matches: string[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: baseDir, depth: 0 }];

  while (queue.length > 0 && matches.length < MAX_WILDCARD_MATCHES) {
    const current = queue.pop();
    if (!current) break;

    let entries;
    try {
      entries = readdirSync(current.dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (matches.length >= MAX_WILDCARD_MATCHES) break;
      const absolute = join(current.dir, entry.name);
      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (current.depth < MAX_WILDCARD_DEPTH) {
          queue.push({ dir: absolute, depth: current.depth + 1 });
        }
        continue;
      }

      if (!entry.isFile()) continue;

      const rel = relative(root, absolute).split(sep).join("/");
      if (rel.startsWith("..")) continue;
      if (!matchRegex.test(rel)) continue;
      matches.push(absolute);
    }
  }

  return matches;
}
