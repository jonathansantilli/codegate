import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import {
  collectLocalTextAnalysisTargets,
  type LocalTextAnalysisTarget,
} from "./layer3-dynamic/local-text-analysis.js";
import { runStaticPipeline } from "./pipeline.js";
import type { StaticFileInput } from "./layer2-static/engine.js";
import { applyReportSummary } from "./report-summary.js";
import { parseConfigFile, type ParseResult } from "./layer1-discovery/config-parser.js";
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
import type { DiscoveryFormat } from "./types/discovery.js";
import type { Finding } from "./types/finding.js";
import type { CodeGateReport } from "./types/report.js";
import type { CodeGateConfig } from "./config.js";
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
}

export interface ScanSurfaceOptions {
  includeUserScope?: boolean;
  homeDir?: string;
}

export interface ScanDiscoveryCandidate {
  reportPath: string;
  absolutePath: string;
  format: DiscoveryFormat;
  tool: string;
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
}

export interface ScanDiscoveryContextOptions {
  includeUserScope?: boolean;
  homeDir?: string;
  parseSelected?: boolean;
  explicitCandidates?: ScanDiscoveryCandidate[];
}

const INFERRED_ARTIFACT_RULES: Array<{
  pattern: RegExp;
  format: DiscoveryFormat;
  tool: string;
}> = [
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

function wildcardToRegex(pattern: string): RegExp {
  let escaped = escapeRegex(pattern);
  escaped = escaped.replace(/\\\*\\\*\//g, "(?:[^/]+/)*");
  escaped = escaped.replace(/\\\*\\\*/g, ".*");
  escaped = escaped.replace(/\\\*/g, "[^/]*");
  return new RegExp(`^${escaped}$`, "u");
}

function normalizePathForMatch(path: string): string {
  return path.split(sep).join("/");
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
  options: { includeUserScope: boolean; homeDir: string },
): ScanDiscoveryCandidate[] {
  const selected = new Map<string, ScanDiscoveryCandidate>();

  const filesByRelativePath = walkedFiles
    .map((filePath) => ({
      absolutePath: filePath,
      relativePath: normalizePathForMatch(relative(absoluteTarget, filePath)),
    }))
    .filter((entry) => !entry.relativePath.startsWith(".."));

  for (const file of filesByRelativePath) {
    for (const candidate of patterns) {
      if (candidate.scope !== "project") {
        continue;
      }
      if (!wildcardToRegex(candidate.pattern).test(file.relativePath)) {
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

  if (!options.includeUserScope) {
    for (const file of filesByRelativePath) {
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

  for (const candidate of patterns) {
    if (candidate.scope !== "user") {
      continue;
    }
    const userPattern = normalizeUserScopePattern(candidate.pattern);
    if (userPattern.includes("*")) {
      for (const match of collectUserScopeWildcardMatches(options.homeDir, userPattern)) {
        const reportPath = toUserReportPath(match.relativePath);
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
    if (!selected.has(reportPath)) {
      selected.set(reportPath, {
        reportPath,
        absolutePath,
        format: candidate.format,
        tool: candidate.tool,
      });
    }
  }

  for (const file of filesByRelativePath) {
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

function mergeExplicitCandidates(
  selected: ScanDiscoveryCandidate[],
  explicitCandidates: ScanDiscoveryCandidate[] | undefined,
): ScanDiscoveryCandidate[] {
  if (!explicitCandidates || explicitCandidates.length === 0) {
    return selected;
  }

  const merged = new Map<string, ScanDiscoveryCandidate>();
  for (const candidate of selected) {
    merged.set(candidate.reportPath, candidate);
  }
  for (const candidate of explicitCandidates) {
    merged.set(candidate.reportPath, candidate);
  }
  return Array.from(merged.values());
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
    parsed: parseConfigFile(candidate.absolutePath, candidate.format),
  }));
}

function ensureParsedCandidates(context: ScanDiscoveryContext): ParsedScanDiscoveryCandidate[] {
  if (!context.parsedCandidates) {
    context.parsedCandidates = parseSelectedCandidates(context.selected);
  }
  return context.parsedCandidates;
}

function makeParseErrorFinding(filePath: string, tool: string, message: string): Finding {
  return {
    rule_id: "parse-error",
    finding_id: `PARSE_ERROR-${filePath}`,
    severity: "LOW",
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
  const selected = mergeExplicitCandidates(
    collectSelectedCandidates(absoluteTarget, walked.files, patterns, {
      includeUserScope: options.includeUserScope === true,
      homeDir: resolve(options.homeDir ?? homedir()),
    }),
    options.explicitCandidates,
  );

  return {
    absoluteTarget,
    kb,
    walked,
    selected,
    parsedCandidates: options.parseSelected ? parseSelectedCandidates(selected) : undefined,
  };
}

export function discoverDeepScanResourcesFromContext(
  context: ScanDiscoveryContext,
): DeepScanResource[] {
  const discovered = new Map<string, DeepScanResource>();
  for (const item of ensureParsedCandidates(context)) {
    if (!item.parsed.ok) {
      continue;
    }
    collectDeepScanResourcesFromParsed(item.parsed.data, item.reportPath, discovered);
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
      textContent: readTextFileUtf8(item.absolutePath),
    })),
  );
}

export async function runScanEngine(input: ScanEngineInput): Promise<CodeGateReport> {
  const context =
    input.discoveryContext ??
    createScanDiscoveryContext(input.scanTarget, input.kb, {
      includeUserScope: input.config.scan_user_scope === true,
      homeDir: input.homeDir,
      parseSelected: true,
    });
  const absoluteTarget = context.absoluteTarget;
  const kb = context.kb;
  const parseErrors: Finding[] = [];
  const staticFiles: StaticFileInput[] = [];

  for (const item of ensureParsedCandidates(context)) {
    if (!item.parsed.ok) {
      parseErrors.push(makeParseErrorFinding(item.reportPath, item.tool, item.parsed.error));
      continue;
    }

    staticFiles.push({
      filePath: item.reportPath,
      format: item.format,
      parsed: item.parsed.data,
      textContent: readTextFileUtf8(item.absolutePath),
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

  const report = runStaticPipeline({
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

  const findings = [...report.findings, ...parseErrors, ...stateResult.findings];
  return applyReportSummary({
    ...report,
    findings,
  });
}
