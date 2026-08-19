import {
  closeSync,
  existsSync,
  openSync,
  readSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import {
  collectLocalTextAnalysisTargets,
  type LocalTextAnalysisTarget,
} from "./layer3-dynamic/local-text-analysis.js";
import { runStaticPipeline } from "./pipeline.js";
import type { StaticFileInput } from "./layer2-static/engine.js";
import { applyReportSummary } from "./report-summary.js";
import {
  parseConfigContent,
  parseConfigFile,
  type ParseResult,
} from "./layer1-discovery/config-parser.js";
import {
  loadKnowledgeBase,
  type KnowledgeBaseLoadResult,
} from "./layer1-discovery/knowledge-base.js";
import { detectTools } from "./layer1-discovery/tool-detector.js";
import { walkProjectTree, type WalkResult } from "./layer1-discovery/file-walker.js";
import {
  evaluateScanStateSnapshots,
  extractMcpServerSnapshots,
  loadScanState,
  saveScanState,
} from "./layer2-static/state/scan-state.js";
import {
  applyInlineIgnoreDirectives,
  collectInlineIgnoreDirectives,
} from "./config/inline-ignore.js";
import { isTrustedDirectory } from "./config/trust.js";
import { normalizeForMatching } from "./layer2-static/text/normalize.js";
import { REMOTE_INSTRUCTION_INDIRECTION_PATTERN } from "./layer2-static/text/threat-patterns.js";
import { withFindingFingerprint } from "./report/finding-fingerprint.js";
import { isGitHubDependabotPath } from "./layer2-static/dependabot/parser.js";
import type { DiscoveryFormat } from "./types/discovery.js";
import type { Finding } from "./types/finding.js";
import type { CodeGateReport } from "./types/report.js";
import type { CodeGateConfig, ScanCollectionKind, ScanCollectionMode } from "./config.js";
import type { DeepScanResource } from "./pipeline.js";

interface CandidatePattern {
  pattern: string;
  format: DiscoveryFormat;
  tool: string;
  scope: "project" | "user";
}

const MCP_SERVER_CONTAINER_KEYS = ["mcpServers", "mcp_servers", "context_servers"] as const;
const REMOTE_MCP_SERVER_ARRAY_KEYS = ["remoteMCPServers", "remote_mcp_servers"] as const;
const USER_SCOPE_WILDCARD_MAX_DEPTH = 6;
const USER_SCOPE_WILDCARD_MAX_FILES = 500;
const SKILL_FILE_NAME = "skill.md";
const SKILL_SIBLING_MAX_DEPTH = 3;
const SKILL_SIBLING_MAX_FILES = 200;
const BINARY_SNIFF_BYTES = 512;

const SKILL_SIBLING_FORMATS: Readonly<Record<string, DiscoveryFormat>> = {
  md: "markdown",
  markdown: "markdown",
  json: "json",
  yaml: "yaml",
  yml: "yaml",
  toml: "toml",
  sh: "text",
  bash: "text",
  zsh: "text",
  ps1: "text",
  py: "text",
  js: "text",
  mjs: "text",
  cjs: "text",
  ts: "text",
  rb: "text",
  txt: "text",
};

export const SKILL_BINARY_KIND = {
  Elf: "elf",
  MachO: "mach-o",
  Pe: "pe",
  Unknown: "binary",
} as const;
export type SkillBinaryKind = (typeof SKILL_BINARY_KIND)[keyof typeof SKILL_BINARY_KIND];

export interface SkillBinaryArtifact {
  reportPath: string;
  kind: SkillBinaryKind;
  executable: boolean;
}

export interface ScanEngineInput {
  version: string;
  scanTarget: string;
  kb?: KnowledgeBaseLoadResult;
  config: CodeGateConfig;
  scanStatePath?: string;
  homeDir?: string;
  discoveryContext?: ScanDiscoveryContext;
}

export interface DeepScanDiscoveryOptions {
  includeUserScope?: boolean;
  homeDir?: string;
  collectModes?: ScanCollectionMode[];
  collectKinds?: ScanCollectionKind[];
}

export interface ScanSurfaceOptions {
  includeUserScope?: boolean;
  homeDir?: string;
  collectModes?: ScanCollectionMode[];
  collectKinds?: ScanCollectionKind[];
}

export interface ScanDiscoveryCandidate {
  reportPath: string;
  absolutePath: string;
  format: DiscoveryFormat;
  tool: string;
  textContent?: string;
}

export interface ParsedScanDiscoveryCandidate extends ScanDiscoveryCandidate {
  parsed: ParseResult;
}

export interface ScanDiscoveryContext {
  absoluteTarget: string;
  kb: KnowledgeBaseLoadResult;
  walked: WalkResult;
  selected: ScanDiscoveryCandidate[];
  parsedCandidates?: ParsedScanDiscoveryCandidate[];
  skillBinaries?: SkillBinaryArtifact[];
}

export interface ScanDiscoveryContextOptions {
  includeUserScope?: boolean;
  homeDir?: string;
  parseSelected?: boolean;
  explicitCandidates?: ScanDiscoveryCandidate[];
  collectModes?: ScanCollectionMode[];
  collectKinds?: ScanCollectionKind[];
}

const INFERRED_ARTIFACT_RULES: Array<{
  pattern: RegExp;
  format: DiscoveryFormat;
  tool: string;
}> = [
  {
    pattern: /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/iu,
    format: "yaml",
    tool: "github-actions",
  },
  {
    pattern: /(?:^|\/)\.github\/dependabot\.ya?ml$/iu,
    format: "yaml",
    tool: "dependabot",
  },
  {
    pattern: /(?:^|\/)action\.ya?ml$/iu,
    format: "yaml",
    tool: "github-actions",
  },
  { pattern: /(?:^|\/)agents\.md$/iu, format: "markdown", tool: "claude-code" },
  { pattern: /(?:^|\/)claude\.md$/iu, format: "markdown", tool: "claude-code" },
  { pattern: /(?:^|\/)codex\.md$/iu, format: "markdown", tool: "codex-cli" },
  { pattern: /(?:^|\/)skill\.md$/iu, format: "markdown", tool: "codex-cli" },
  { pattern: /(?:^|\/)[^/]+\.mdc$/iu, format: "markdown", tool: "cursor" },
  { pattern: /(?:^|\/)plugins\.json$/iu, format: "json", tool: "opencode" },
  { pattern: /(?:^|\/)extensions\.json$/iu, format: "json", tool: "vscode" },
  { pattern: /(?:^|\/)marketplace\.json$/iu, format: "json", tool: "roo-code" },
  { pattern: /(?:^|\/)product\.json$/iu, format: "json", tool: "kiro" },
];

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.*]/g, "\\$&");
}

const wildcardRegexCache = new Map<string, RegExp>();

function wildcardToRegex(pattern: string): RegExp {
  const cached = wildcardRegexCache.get(pattern);
  if (cached) {
    return cached;
  }
  let escaped = escapeRegex(pattern);
  escaped = escaped.replace(/\\\*\\\*\//g, "(?:[^/]+/)*");
  escaped = escaped.replace(/\\\*\\\*/g, ".*");
  escaped = escaped.replace(/\\\*/g, "[^/]*");
  const regex = new RegExp(`^${escaped}$`, "u");
  wildcardRegexCache.set(pattern, regex);
  return regex;
}

function normalizePathForMatch(path: string): string {
  return path.split(sep).join("/");
}

function normalizeCollectionKinds(
  input: ScanCollectionKind[] | undefined,
): Set<ScanCollectionKind> | undefined {
  if (!input || input.length === 0) {
    return undefined;
  }

  return new Set(input);
}

function normalizeUserScopePattern(pattern: string): string {
  return normalizePathForMatch(pattern).replace(/^~\//u, "").replace(/^\/+/u, "");
}

function gatherCandidatePatterns(kb: KnowledgeBaseLoadResult): CandidatePattern[] {
  const candidates: CandidatePattern[] = [];

  for (const entry of kb.entries) {
    for (const configPath of entry.config_paths) {
      candidates.push({
        pattern: normalizePathForMatch(configPath.path),
        format: configPath.format,
        tool: entry.tool,
        scope: configPath.scope,
      });
    }

    for (const skillPath of entry.skill_paths ?? []) {
      const format: DiscoveryFormat = skillPath.path.endsWith(".md") ? "markdown" : "text";
      candidates.push({
        pattern: normalizePathForMatch(skillPath.path),
        format,
        tool: entry.tool,
        scope: skillPath.scope,
      });
    }
  }

  return candidates;
}

function isWorkflowCollectionCandidate(reportPath: string): boolean {
  return /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/iu.test(normalizePathForMatch(reportPath));
}

function isActionCollectionCandidate(reportPath: string): boolean {
  const fileName = basename(normalizePathForMatch(reportPath)).toLowerCase();
  return fileName === "action.yml" || fileName === "action.yaml";
}

function inferCollectionKind(reportPath: string): ScanCollectionKind | null {
  if (isWorkflowCollectionCandidate(reportPath)) {
    return "workflows";
  }
  if (isActionCollectionCandidate(reportPath)) {
    return "actions";
  }
  if (isGitHubDependabotPath(reportPath)) {
    return "dependabot";
  }
  return null;
}

function matchesCollectionKinds(
  reportPath: string,
  collectKinds: Set<ScanCollectionKind> | undefined,
): boolean {
  if (!collectKinds) {
    return true;
  }

  const kind = inferCollectionKind(reportPath);
  return kind !== null && collectKinds.has(kind);
}

function isRegularFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function toUserReportPath(pattern: string): string {
  const normalized = normalizeUserScopePattern(pattern);
  return `~/${normalized}`;
}

function userScopeWildcardBaseDir(pattern: string): string {
  const normalized = normalizeUserScopePattern(pattern);
  const wildcardIndex = normalized.indexOf("*");
  if (wildcardIndex < 0) {
    return normalized;
  }

  const prefix = normalized.slice(0, wildcardIndex);
  const trimmedPrefix = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  if (trimmedPrefix.length === 0) {
    return "";
  }

  const slashIndex = trimmedPrefix.lastIndexOf("/");
  return slashIndex >= 0 ? trimmedPrefix.slice(0, slashIndex) : "";
}

interface UserWildcardMatch {
  absolutePath: string;
  relativePath: string;
}

function collectUserScopeWildcardMatches(homeDir: string, pattern: string): UserWildcardMatch[] {
  const normalizedPattern = normalizeUserScopePattern(pattern);
  const matchRegex = wildcardToRegex(normalizedPattern);
  const baseDir = resolve(homeDir, userScopeWildcardBaseDir(normalizedPattern));

  if (!existsSync(baseDir)) {
    return [];
  }

  try {
    if (!statSync(baseDir).isDirectory()) {
      return [];
    }
  } catch {
    return [];
  }

  const matches: UserWildcardMatch[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: baseDir, depth: 0 }];

  while (queue.length > 0 && matches.length < USER_SCOPE_WILDCARD_MAX_FILES) {
    const current = queue.pop();
    if (!current) {
      break;
    }

    let entries;
    try {
      entries = readdirSync(current.dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (matches.length >= USER_SCOPE_WILDCARD_MAX_FILES) {
        break;
      }

      const absolutePath = join(current.dir, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }

      if (entry.isDirectory()) {
        if (current.depth < USER_SCOPE_WILDCARD_MAX_DEPTH) {
          queue.push({ dir: absolutePath, depth: current.depth + 1 });
        }
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const relativePath = normalizePathForMatch(relative(homeDir, absolutePath));
      if (relativePath.startsWith("..")) {
        continue;
      }
      if (!matchRegex.test(relativePath)) {
        continue;
      }

      matches.push({ absolutePath, relativePath });
    }
  }

  return matches;
}

function collectSelectedCandidates(
  absoluteTarget: string,
  walkedFiles: string[],
  patterns: CandidatePattern[],
  options: {
    includeUserScope: boolean;
    homeDir: string;
    collectModes: Set<ScanCollectionMode>;
    collectKinds?: Set<ScanCollectionKind>;
  },
): ScanDiscoveryCandidate[] {
  const selected = new Map<string, ScanDiscoveryCandidate>();
  const includeAll = options.collectModes.has("all");
  const includeProject =
    includeAll || options.collectModes.has("default") || options.collectModes.has("project");
  const includeUser =
    includeAll ||
    options.collectModes.has("user") ||
    (options.collectModes.has("default") && options.includeUserScope);

  const filesByRelativePath = walkedFiles
    .map((filePath) => ({
      absolutePath: filePath,
      relativePath: normalizePathForMatch(relative(absoluteTarget, filePath)),
    }))
    .filter((entry) => !entry.relativePath.startsWith(".."));

  const projectPatterns = patterns
    .filter((candidate) => candidate.scope === "project")
    .map((candidate) => ({ candidate, regex: wildcardToRegex(candidate.pattern) }));

  for (const file of filesByRelativePath) {
    if (!includeProject) {
      continue;
    }
    for (const { candidate, regex } of projectPatterns) {
      if (!regex.test(file.relativePath)) {
        continue;
      }
      if (!matchesCollectionKinds(file.relativePath, options.collectKinds)) {
        continue;
      }
      if (!selected.has(file.relativePath)) {
        selected.set(file.relativePath, {
          reportPath: file.relativePath,
          absolutePath: file.absolutePath,
          format: candidate.format,
          tool: candidate.tool,
        });
      }
    }
  }

  if (!includeUser) {
    for (const file of filesByRelativePath) {
      if (!includeProject) {
        continue;
      }
      if (!matchesCollectionKinds(file.relativePath, options.collectKinds)) {
        continue;
      }
      if (selected.has(file.relativePath)) {
        continue;
      }

      const inferred = inferArtifactCandidate(file.relativePath, file.absolutePath);
      if (!inferred) {
        continue;
      }

      selected.set(file.relativePath, inferred);
    }

    return Array.from(selected.values());
  }

  if (includeUser) {
    for (const candidate of patterns) {
      if (candidate.scope !== "user") {
        continue;
      }
      const userPattern = normalizeUserScopePattern(candidate.pattern);
      if (userPattern.includes("*")) {
        for (const match of collectUserScopeWildcardMatches(options.homeDir, userPattern)) {
          const reportPath = toUserReportPath(match.relativePath);
          if (!matchesCollectionKinds(reportPath, options.collectKinds)) {
            continue;
          }
          if (!selected.has(reportPath)) {
            selected.set(reportPath, {
              reportPath,
              absolutePath: match.absolutePath,
              format: candidate.format,
              tool: candidate.tool,
            });
          }
        }
        continue;
      }
      const absolutePath = resolve(options.homeDir, userPattern);
      if (!existsSync(absolutePath) || !isRegularFile(absolutePath)) {
        continue;
      }
      const reportPath = toUserReportPath(userPattern);
      if (!matchesCollectionKinds(reportPath, options.collectKinds)) {
        continue;
      }
      if (!selected.has(reportPath)) {
        selected.set(reportPath, {
          reportPath,
          absolutePath,
          format: candidate.format,
          tool: candidate.tool,
        });
      }
    }
  }

  for (const file of filesByRelativePath) {
    if (!includeProject && !includeAll) {
      continue;
    }
    if (!matchesCollectionKinds(file.relativePath, options.collectKinds)) {
      continue;
    }
    if (selected.has(file.relativePath)) {
      continue;
    }

    const inferred = inferArtifactCandidate(file.relativePath, file.absolutePath);
    if (!inferred) {
      continue;
    }

    selected.set(file.relativePath, inferred);
  }

  return Array.from(selected.values());
}

function normalizeCollectionModes(
  input: ScanCollectionMode[] | undefined,
): Set<ScanCollectionMode> {
  const normalized = new Set<ScanCollectionMode>();
  for (const mode of input ?? []) {
    normalized.add(mode);
  }
  if (normalized.size === 0) {
    normalized.add("default");
  }
  return normalized;
}

function mergeExplicitCandidates(
  selected: ScanDiscoveryCandidate[],
  explicitCandidates: ScanDiscoveryCandidate[] | undefined,
  collectKinds?: Set<ScanCollectionKind>,
): ScanDiscoveryCandidate[] {
  if (!explicitCandidates || explicitCandidates.length === 0) {
    return selected;
  }

  const merged = new Map<string, ScanDiscoveryCandidate>();
  for (const candidate of selected) {
    merged.set(candidate.reportPath, candidate);
  }
  for (const candidate of explicitCandidates) {
    if (!matchesCollectionKinds(candidate.reportPath, collectKinds)) {
      continue;
    }
    merged.set(candidate.reportPath, candidate);
  }
  return Array.from(merged.values());
}

interface SniffResult {
  binaryKind: SkillBinaryKind | null;
  hasShebang: boolean;
}

function sniffFileHead(path: string): SniffResult {
  const buffer = Buffer.alloc(BINARY_SNIFF_BYTES);
  let bytesRead: number;
  try {
    const fd = openSync(path, "r");
    try {
      bytesRead = readSync(fd, buffer, 0, BINARY_SNIFF_BYTES, 0);
    } finally {
      closeSync(fd);
    }
  } catch {
    return { binaryKind: null, hasShebang: false };
  }

  const head = buffer.subarray(0, bytesRead);
  const hasShebang = bytesRead >= 2 && head[0] === 0x23 && head[1] === 0x21;

  if (
    bytesRead >= 4 &&
    head[0] === 0x7f &&
    head[1] === 0x45 &&
    head[2] === 0x4c &&
    head[3] === 0x46
  ) {
    return { binaryKind: SKILL_BINARY_KIND.Elf, hasShebang: false };
  }
  const magic = bytesRead >= 4 ? head.readUInt32BE(0) : 0;
  if (
    magic === 0xfeedface ||
    magic === 0xfeedfacf ||
    magic === 0xcefaedfe ||
    magic === 0xcffaedfe ||
    magic === 0xcafebabe
  ) {
    return { binaryKind: SKILL_BINARY_KIND.MachO, hasShebang: false };
  }
  if (bytesRead >= 2 && head[0] === 0x4d && head[1] === 0x5a) {
    return { binaryKind: SKILL_BINARY_KIND.Pe, hasShebang: false };
  }
  if (head.includes(0)) {
    return { binaryKind: SKILL_BINARY_KIND.Unknown, hasShebang: false };
  }
  return { binaryKind: null, hasShebang };
}

function isSkillCandidate(candidate: ScanDiscoveryCandidate): boolean {
  return basename(normalizePathForMatch(candidate.reportPath)).toLowerCase() === SKILL_FILE_NAME;
}

function siblingReportPath(candidate: ScanDiscoveryCandidate, siblingAbsolute: string): string {
  const skillDir = dirname(candidate.absolutePath);
  const relFromSkillDir = normalizePathForMatch(relative(skillDir, siblingAbsolute));
  const normalizedReport = normalizePathForMatch(candidate.reportPath);
  const slashIndex = normalizedReport.lastIndexOf("/");
  const parentReport = slashIndex >= 0 ? normalizedReport.slice(0, slashIndex) : "";
  return parentReport ? `${parentReport}/${relFromSkillDir}` : relFromSkillDir;
}

/**
 * Skills ship payloads next to SKILL.md (helper scripts, nested docs,
 * sometimes binaries). Collect text-like siblings as scan candidates so the
 * rule-file detectors see them, and record binary artifacts for reporting.
 */
function collectSkillSiblings(selected: ScanDiscoveryCandidate[]): {
  candidates: ScanDiscoveryCandidate[];
  binaries: SkillBinaryArtifact[];
} {
  const known = new Set(selected.map((candidate) => normalizePathForMatch(candidate.reportPath)));
  const candidates: ScanDiscoveryCandidate[] = [];
  const binaries: SkillBinaryArtifact[] = [];
  const visitedDirs = new Set<string>();

  for (const skillCandidate of selected.filter(isSkillCandidate)) {
    const skillDir = dirname(skillCandidate.absolutePath);
    if (visitedDirs.has(skillDir)) {
      continue;
    }
    visitedDirs.add(skillDir);

    let filesSeen = 0;
    const queue: Array<{ dir: string; depth: number }> = [{ dir: skillDir, depth: 0 }];
    while (queue.length > 0 && filesSeen < SKILL_SIBLING_MAX_FILES) {
      const current = queue.pop();
      if (!current) {
        break;
      }

      let entries;
      try {
        entries = readdirSync(current.dir, { withFileTypes: true });
      } catch {
        continue;
      }

      for (const entry of entries) {
        if (filesSeen >= SKILL_SIBLING_MAX_FILES) {
          break;
        }
        if (entry.isSymbolicLink()) {
          continue;
        }
        const absolutePath = join(current.dir, entry.name);
        if (entry.isDirectory()) {
          if (current.depth < SKILL_SIBLING_MAX_DEPTH) {
            queue.push({ dir: absolutePath, depth: current.depth + 1 });
          }
          continue;
        }
        if (!entry.isFile() || absolutePath === skillCandidate.absolutePath) {
          continue;
        }
        filesSeen += 1;

        const reportPath = siblingReportPath(skillCandidate, absolutePath);
        if (known.has(reportPath)) {
          continue;
        }

        const sniffed = sniffFileHead(absolutePath);
        if (sniffed.binaryKind) {
          let executable: boolean;
          try {
            executable = (statSync(absolutePath).mode & 0o111) !== 0;
          } catch {
            executable = false;
          }
          binaries.push({ reportPath, kind: sniffed.binaryKind, executable });
          continue;
        }

        const extension = entry.name.includes(".")
          ? (entry.name.split(".").pop() ?? "").toLowerCase()
          : "";
        const format = SKILL_SIBLING_FORMATS[extension] ?? (sniffed.hasShebang ? "text" : null);
        if (!format) {
          continue;
        }

        known.add(reportPath);
        candidates.push({
          reportPath,
          absolutePath,
          format,
          tool: skillCandidate.tool,
        });
      }
    }
  }

  return { candidates, binaries };
}

function inferArtifactCandidate(
  relativePath: string,
  absolutePath: string,
): ScanDiscoveryCandidate | null {
  for (const rule of INFERRED_ARTIFACT_RULES) {
    if (!rule.pattern.test(relativePath)) {
      continue;
    }

    return {
      reportPath: relativePath,
      absolutePath,
      format: rule.format,
      tool: rule.tool,
    };
  }

  return null;
}

function parseSelectedCandidates(
  selected: ScanDiscoveryCandidate[],
): ParsedScanDiscoveryCandidate[] {
  return selected.map((candidate) => ({
    ...candidate,
    parsed:
      candidate.textContent !== undefined
        ? parseConfigContent(candidate.textContent, candidate.format)
        : parseConfigFile(candidate.absolutePath, candidate.format),
  }));
}

function ensureParsedCandidates(context: ScanDiscoveryContext): ParsedScanDiscoveryCandidate[] {
  if (!context.parsedCandidates) {
    context.parsedCandidates = parseSelectedCandidates(context.selected);
  }
  return context.parsedCandidates;
}

function makeUntrustedProjectConfigFinding(ignoredSettings: string[]): Finding {
  return {
    rule_id: "untrusted-project-config",
    finding_id: "UNTRUSTED_PROJECT_CONFIG-.codegate.json",
    severity: "INFO",
    category: "CONFIG_CHANGE",
    layer: "L1",
    file_path: ".codegate.json",
    location: { field: ignoredSettings.join(", ") },
    description:
      `Ignored ${ignoredSettings.length} policy setting(s) from untrusted project config: ` +
      `${ignoredSettings.join(", ")}. Project config in untrusted directories may only set ` +
      "presentation options. Run `codegate trust <dir>` to honor its policy settings.",
    affected_tools: [],
    cve: null,
    owasp: [],
    cwe: "CWE-807",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    suppressed: false,
  };
}

function makeSkillBinaryFinding(artifact: SkillBinaryArtifact): Finding {
  const isExecutableFormat = artifact.kind !== SKILL_BINARY_KIND.Unknown;
  const severity: Finding["severity"] =
    artifact.executable || isExecutableFormat ? "HIGH" : "MEDIUM";
  const kindLabel = isExecutableFormat ? `${artifact.kind} executable` : "binary file";

  return {
    rule_id: "skill-binary-payload",
    finding_id: `SKILL_BINARY-${artifact.reportPath}`,
    severity,
    category: "COMMAND_EXEC",
    layer: "L1",
    file_path: artifact.reportPath,
    location: { field: "content" },
    description:
      `Skill directory ships a ${kindLabel}${artifact.executable ? " with execute permissions" : ""}. ` +
      "Binary payloads cannot be reviewed as text and have no place in an instruction skill.",
    affected_tools: ["claude-code", "codex-cli", "opencode", "cursor"],
    cve: null,
    owasp: ["ASI02"],
    cwe: "CWE-506",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["quarantine_file"],
    metadata: {
      sources: [artifact.reportPath],
      risk_tags: ["skill", "binary-payload"],
      origin: "skill-siblings",
    },
    suppressed: false,
  };
}

function makeParseErrorFinding(
  filePath: string,
  tool: string,
  message: string,
  strictCollection: boolean,
): Finding {
  return {
    rule_id: "parse-error",
    finding_id: `PARSE_ERROR-${filePath}`,
    severity: strictCollection ? "HIGH" : "LOW",
    category: "PARSE_ERROR",
    layer: "L1",
    file_path: filePath,
    location: { field: "parse" },
    description: message,
    affected_tools: [tool],
    cve: null,
    owasp: ["ASI06"],
    cwe: "CWE-20",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    suppressed: false,
  };
}

function readTextFileUtf8(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

function readCandidateText(candidate: ScanDiscoveryCandidate): string {
  return candidate.textContent ?? readTextFileUtf8(candidate.absolutePath);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isHttpLikeUrl(value: string): boolean {
  return /^https?:\/\//iu.test(value);
}

function firstNonFlag(tokens: string[], startIndex = 0): string | null {
  for (let index = startIndex; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (typeof token !== "string" || token.length === 0 || token.startsWith("-")) {
      continue;
    }
    return token;
  }
  return null;
}

function commandResourceFromTokens(
  command: string[],
): { id: string; kind: "npm" | "pypi"; locator: string; preview: string } | null {
  if (command.length === 0) {
    return null;
  }
  const launcher = command[0]?.toLowerCase();

  if (launcher === "npx") {
    const locator = firstNonFlag(command, 1);
    if (!locator) {
      return null;
    }
    return {
      id: `npm:${locator}`,
      kind: "npm",
      locator,
      preview: `npm view ${locator} --json`,
    };
  }

  if (launcher === "uvx" || launcher === "pipx") {
    const locator = firstNonFlag(command, 1);
    if (!locator) {
      return null;
    }
    return {
      id: `pypi:${locator}`,
      kind: "pypi",
      locator,
      preview: `https://pypi.org/pypi/${locator}/json`,
    };
  }

  return null;
}

function inferHttpKind(url: string): "http" | "sse" {
  const lower = url.toLowerCase();
  if (lower.includes("sse") || lower.includes("eventstream") || lower.includes("event-stream")) {
    return "sse";
  }
  return "http";
}

function collectMcpServerContainers(
  value: Record<string, unknown>,
): Array<{ key: string; servers: Record<string, unknown> }> {
  const containers: Array<{ key: string; servers: Record<string, unknown> }> = [];
  for (const key of MCP_SERVER_CONTAINER_KEYS) {
    const candidate = value[key];
    if (!isRecord(candidate)) {
      continue;
    }
    containers.push({ key, servers: candidate });
  }
  return containers;
}

function collectRemoteMcpServerArrays(
  value: Record<string, unknown>,
): Array<{ key: string; servers: Array<Record<string, unknown>> }> {
  const arrays: Array<{ key: string; servers: Array<Record<string, unknown>> }> = [];
  for (const key of REMOTE_MCP_SERVER_ARRAY_KEYS) {
    const candidate = value[key];
    if (!Array.isArray(candidate)) {
      continue;
    }
    const servers = candidate.filter((entry): entry is Record<string, unknown> => isRecord(entry));
    if (servers.length === 0) {
      continue;
    }
    arrays.push({ key, servers });
  }
  return arrays;
}

function collectDeepScanResourcesFromParsed(
  value: unknown,
  filePath: string,
  resources: Map<string, DeepScanResource>,
): void {
  if (!isRecord(value)) {
    return;
  }

  for (const container of collectMcpServerContainers(value)) {
    for (const [serverName, config] of Object.entries(container.servers)) {
      if (!isRecord(config)) {
        continue;
      }

      if (typeof config.url === "string" && isHttpLikeUrl(config.url)) {
        const kind = inferHttpKind(config.url);
        const id = `${kind}:${config.url}`;
        if (!resources.has(id)) {
          resources.set(id, {
            id,
            request: {
              id,
              kind,
              locator: config.url,
            },
            commandPreview: `GET ${config.url}  (from ${filePath} -> ${container.key}.${serverName}.url)`,
          });
        }
      }

      if (
        Array.isArray(config.command) &&
        config.command.length > 0 &&
        config.command.every((entry) => typeof entry === "string")
      ) {
        const commandResource = commandResourceFromTokens(config.command as string[]);
        if (!commandResource || resources.has(commandResource.id)) {
          continue;
        }

        resources.set(commandResource.id, {
          id: commandResource.id,
          request: {
            id: commandResource.id,
            kind: commandResource.kind,
            locator: commandResource.locator,
          },
          commandPreview: `${commandResource.preview}  (from ${filePath} -> ${container.key}.${serverName}.command)`,
        });
      }
    }
  }

  for (const remoteArray of collectRemoteMcpServerArrays(value)) {
    remoteArray.servers.forEach((config, index) => {
      if (typeof config.url !== "string" || !isHttpLikeUrl(config.url)) {
        return;
      }
      const kind = inferHttpKind(config.url);
      const id = `${kind}:${config.url}`;
      if (resources.has(id)) {
        return;
      }
      resources.set(id, {
        id,
        request: {
          id,
          kind,
          locator: config.url,
        },
        commandPreview: `GET ${config.url}  (from ${filePath} -> ${remoteArray.key}.${index}.url)`,
      });
    });
  }

  for (const nested of Object.values(value)) {
    collectDeepScanResourcesFromParsed(nested, filePath, resources);
  }
}

export function discoverDeepScanResources(
  scanTarget: string,
  kbInput?: KnowledgeBaseLoadResult,
  options: DeepScanDiscoveryOptions = {},
): DeepScanResource[] {
  const context = createScanDiscoveryContext(scanTarget, kbInput, {
    includeUserScope: options.includeUserScope,
    homeDir: options.homeDir,
    collectModes: options.collectModes,
    collectKinds: options.collectKinds,
    parseSelected: true,
  });
  return discoverDeepScanResourcesFromContext(context);
}

export function createScanDiscoveryContext(
  scanTarget: string,
  kbInput?: KnowledgeBaseLoadResult,
  options: ScanDiscoveryContextOptions = {},
): ScanDiscoveryContext {
  const absoluteTarget = resolve(scanTarget);
  const targetStat = statSync(absoluteTarget);
  if (!targetStat.isDirectory()) {
    throw new Error(`Scan target is not a directory: ${scanTarget}`);
  }

  const kb = kbInput ?? loadKnowledgeBase();
  const patterns = gatherCandidatePatterns(kb);
  const walked = walkProjectTree(absoluteTarget);
  const collectModes = normalizeCollectionModes(options.collectModes);
  const collectKinds = normalizeCollectionKinds(options.collectKinds);
  const explicitOnly = collectModes.size === 1 && collectModes.has("explicit");
  const baseSelected = mergeExplicitCandidates(
    explicitOnly
      ? []
      : collectSelectedCandidates(absoluteTarget, walked.files, patterns, {
          includeUserScope: options.includeUserScope === true,
          homeDir: resolve(options.homeDir ?? homedir()),
          collectModes,
          collectKinds,
        }),
    options.explicitCandidates,
    collectKinds,
  );
  const skillSiblings = collectSkillSiblings(baseSelected);
  const selected = [...baseSelected, ...skillSiblings.candidates];

  return {
    absoluteTarget,
    kb,
    walked,
    selected,
    parsedCandidates: options.parseSelected ? parseSelectedCandidates(selected) : undefined,
    skillBinaries: skillSiblings.binaries,
  };
}

function collectIndirectionUrlResources(
  textContent: string,
  filePath: string,
  resources: Map<string, DeepScanResource>,
): void {
  const lines = textContent.split(/\r?\n/u);
  for (const line of lines) {
    const normalized = normalizeForMatching(line);
    if (!REMOTE_INSTRUCTION_INDIRECTION_PATTERN.test(normalized)) {
      continue;
    }
    const urlMatch = line.match(/https?:\/\/[^\s)\]"'`<>]+/iu);
    if (!urlMatch) {
      continue;
    }
    const url = urlMatch[0];
    const kind = inferHttpKind(url);
    const id = `${kind}:${url}`;
    if (resources.has(id)) {
      continue;
    }
    resources.set(id, {
      id,
      request: { id, kind, locator: url },
      commandPreview: `GET ${url}  (from ${filePath} -> remote instruction indirection)`,
    });
  }
}

export function discoverDeepScanResourcesFromContext(
  context: ScanDiscoveryContext,
): DeepScanResource[] {
  const discovered = new Map<string, DeepScanResource>();
  for (const item of ensureParsedCandidates(context)) {
    if (item.parsed.ok) {
      collectDeepScanResourcesFromParsed(item.parsed.data, item.reportPath, discovered);
    }
    if (item.format === "markdown" || item.format === "text") {
      collectIndirectionUrlResources(readCandidateText(item), item.reportPath, discovered);
    }
  }

  return Array.from(discovered.values()).sort((a, b) => a.id.localeCompare(b.id));
}

export function collectScanSurface(
  scanTarget: string,
  kbInput?: KnowledgeBaseLoadResult,
  options: ScanSurfaceOptions = {},
): string[] {
  const context = createScanDiscoveryContext(scanTarget, kbInput, {
    includeUserScope: options.includeUserScope === true,
    homeDir: options.homeDir,
    collectModes: options.collectModes,
    collectKinds: options.collectKinds,
  });

  const surface = new Set<string>(context.walked.files);
  for (const item of context.selected) {
    surface.add(item.absolutePath);
  }

  return Array.from(surface).sort((left, right) => left.localeCompare(right));
}

export function discoverLocalTextAnalysisTargetsFromContext(
  context: ScanDiscoveryContext,
): LocalTextAnalysisTarget[] {
  return collectLocalTextAnalysisTargets(
    context.selected.map((item) => ({
      reportPath: item.reportPath,
      absolutePath: item.absolutePath,
      format: item.format,
      textContent: readCandidateText(item),
    })),
  );
}

export async function runScanEngine(input: ScanEngineInput): Promise<CodeGateReport> {
  const context =
    input.discoveryContext ??
    createScanDiscoveryContext(input.scanTarget, input.kb, {
      includeUserScope: input.config.scan_user_scope === true,
      collectModes: input.config.scan_collection_modes,
      collectKinds: input.config.scan_collection_kinds,
      homeDir: input.homeDir,
      parseSelected: true,
    });
  const absoluteTarget = context.absoluteTarget;
  const kb = context.kb;
  const parseErrors: Finding[] = [];
  const staticFiles: StaticFileInput[] = [];

  for (const item of ensureParsedCandidates(context)) {
    if (!item.parsed.ok) {
      parseErrors.push(
        makeParseErrorFinding(
          item.reportPath,
          item.tool,
          item.parsed.error,
          input.config.strict_collection === true,
        ),
      );
      continue;
    }

    staticFiles.push({
      filePath: item.reportPath,
      format: item.format,
      parsed: item.parsed.data,
      textContent: readCandidateText(item),
    });
  }

  const filesByRelativePath = context.walked.files
    .map((filePath) => ({
      absolutePath: filePath,
      relativePath: normalizePathForMatch(relative(absoluteTarget, filePath)),
    }))
    .filter((entry) => !entry.relativePath.startsWith(".."));

  const hooks = filesByRelativePath
    .filter((entry) => entry.relativePath.startsWith(".git/hooks/"))
    .map((entry) => {
      const mode = statSync(entry.absolutePath).mode;
      return {
        path: entry.relativePath,
        content: readTextFileUtf8(entry.absolutePath),
        executable: (mode & 0o111) !== 0,
      };
    });

  const report = await runStaticPipeline({
    version: input.version,
    kbVersion: kb.schemaVersion,
    scanTarget: input.scanTarget,
    toolsDetected: detectTools(undefined, { includeVersions: false })
      .filter((tool) => tool.installed)
      .map((tool) => tool.tool),
    projectRoot: absoluteTarget,
    files: staticFiles,
    symlinkEscapes: context.walked.symlinkEscapes.map((entry) => ({
      path: normalizePathForMatch(relative(absoluteTarget, entry.path)),
      target: entry.target,
    })),
    hooks,
    config: {
      knownSafeMcpServers: input.config.known_safe_mcp_servers,
      knownSafeFormatters: input.config.known_safe_formatters,
      knownSafeLspServers: input.config.known_safe_lsp_servers,
      knownSafeHooks: input.config.known_safe_hooks,
      blockedCommands: input.config.blocked_commands,
      trustedApiDomains: input.config.trusted_api_domains,
      unicodeAnalysis: input.config.unicode_analysis,
      checkIdeSettings: input.config.check_ide_settings,
      rulePackPaths: input.config.rule_pack_paths,
      allowedRules: input.config.allowed_rules,
      skipRules: input.config.skip_rules,
      persona: input.config.persona,
      runtimeMode: input.config.runtime_mode,
      workflowAuditsEnabled: input.config.workflow_audits?.enabled === true,
      rulePolicies: input.config.rules,
    },
  });

  const snapshots = new Map<string, ReturnType<typeof extractMcpServerSnapshots>[number]>();
  for (const file of staticFiles) {
    for (const snapshot of extractMcpServerSnapshots(file.filePath, file.parsed)) {
      snapshots.set(snapshot.serverId, snapshot);
    }
  }

  const previousState = loadScanState(input.scanStatePath);
  const stateResult = evaluateScanStateSnapshots({
    snapshots: Array.from(snapshots.values()),
    previousState,
  });
  saveScanState(stateResult.nextState, input.scanStatePath);

  const trustedTarget =
    input.config.project_config_trusted ??
    isTrustedDirectory(absoluteTarget, input.config.trusted_directories);
  const inlineIgnores = collectInlineIgnoreDirectives(
    staticFiles.map((file) => ({
      filePath: file.filePath,
      textContent: file.textContent,
    })),
  );
  const ignoredProjectSettings = input.config.ignored_project_settings ?? [];
  const configNoticeFindings =
    ignoredProjectSettings.length > 0
      ? [withFindingFingerprint(makeUntrustedProjectConfigFinding(ignoredProjectSettings))]
      : [];
  const skillBinaryFindings = (context.skillBinaries ?? []).map((artifact) =>
    withFindingFingerprint(makeSkillBinaryFinding(artifact)),
  );
  const findings = applyInlineIgnoreDirectives(
    [
      ...report.findings,
      ...parseErrors,
      ...stateResult.findings,
      ...configNoticeFindings,
      ...skillBinaryFindings,
    ],
    inlineIgnores,
    { trustedTarget },
  );
  return applyReportSummary({
    ...report,
    findings,
  });
}
