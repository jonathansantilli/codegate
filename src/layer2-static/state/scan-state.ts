import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import type { Finding } from "../../types/finding.js";

export interface ScanStateServerEntry {
  config_hash: string;
  config_path: string;
  first_seen: string;
  last_seen: string;
}

export interface ScanState {
  servers: Record<string, ScanStateServerEntry>;
}

export interface McpServerSnapshot {
  serverId: string;
  serverName: string;
  configHash: string;
  configPath: string;
  serverPath?: string;
}

export interface EvaluateScanStateSnapshotsInput {
  snapshots: McpServerSnapshot[];
  previousState: ScanState;
  nowIso?: string;
}

export interface EvaluateScanStateSnapshotsResult {
  findings: Finding[];
  nextState: ScanState;
}

const LAUNCHERS = new Set(["npx", "uvx", "node", "python", "python3", "deno", "bun"]);
const MCP_SERVER_CONTAINER_KEYS = ["mcpServers", "mcp_servers", "context_servers"] as const;
const REMOTE_MCP_SERVER_ARRAY_KEYS = ["remoteMCPServers", "remote_mcp_servers"] as const;

function defaultPath(): string {
  return resolve(homedir(), ".codegate", "scan-state.json");
}

function expandHomePath(path: string): string {
  if (path === "~") {
    return homedir();
  }
  if (path.startsWith("~/")) {
    return resolve(homedir(), path.slice(2));
  }
  return path;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const entries = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`);
  return `{${entries.join(",")}}`;
}

function sha256(input: string): string {
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}

function extractPackageFromPath(token: string): string | null {
  const normalized = token.replaceAll("\\", "/");
  const scopedMatch = normalized.match(/node_modules\/(@[^/]+\/[^/]+)/u);
  if (scopedMatch?.[1]) {
    return scopedMatch[1];
  }
  const plainMatch = normalized.match(/node_modules\/([^/]+)/u);
  return plainMatch?.[1] ?? null;
}

function extractIdentifierFromCommand(command: string[]): string | null {
  for (const token of command) {
    if (token.startsWith("-")) {
      continue;
    }
    if (LAUNCHERS.has(token)) {
      continue;
    }
    const fromPath = extractPackageFromPath(token);
    if (fromPath) {
      return fromPath;
    }
    return token;
  }
  return null;
}

function normalizeIdentifier(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return "";
  }

  const fromPath = extractPackageFromPath(trimmed);
  const candidate = (fromPath ?? trimmed)
    .replaceAll("\\", "/")
    .replace(/[#?].*$/u, "")
    .replace(/\/+$/u, "");

  const looksLikePackageOrTool = /^@?[a-z0-9._-]+(?:\/[a-z0-9._-]+)?$/iu.test(candidate);
  return looksLikePackageOrTool ? candidate.toLowerCase() : candidate;
}

function normalizedUrlServerId(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) {
    return "url:";
  }

  try {
    const parsed = new URL(trimmed);
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    if (
      (parsed.protocol === "https:" && parsed.port === "443") ||
      (parsed.protocol === "http:" && parsed.port === "80")
    ) {
      parsed.port = "";
    }
    const normalizedPath = parsed.pathname.replace(/\/{2,}/gu, "/");
    parsed.pathname =
      normalizedPath.length > 1 ? normalizedPath.replace(/\/+$/u, "") : normalizedPath;
    const normalizedParams = Array.from(parsed.searchParams.entries()).sort(
      ([leftKey, leftValue], [rightKey, rightValue]) => {
        if (leftKey === rightKey) {
          return leftValue.localeCompare(rightValue);
        }
        return leftKey.localeCompare(rightKey);
      },
    );
    parsed.search = "";
    for (const [key, value] of normalizedParams) {
      parsed.searchParams.append(key, value);
    }
    parsed.hash = "";
    return `url:${parsed.toString()}`;
  } catch {
    return `url:${trimmed}`;
  }
}

function makeStateFinding(
  kind: "NEW_SERVER" | "CONFIG_CHANGE",
  snapshot: McpServerSnapshot,
  previousLastSeen: string | null,
): Finding {
  const locationField = snapshot.serverPath ?? `mcpServers.${snapshot.serverName}`;
  if (kind === "NEW_SERVER") {
    return {
      rule_id: "mcp-server-first-seen",
      finding_id: `NEW_SERVER-${snapshot.serverId}`,
      severity: "INFO",
      category: "NEW_SERVER",
      layer: "L2",
      file_path: snapshot.configPath,
      location: { field: locationField },
      description: `MCP server "${snapshot.serverId}" first seen in this project. Not previously scanned.`,
      affected_tools: ["claude-code", "cursor", "windsurf", "codex-cli", "opencode"],
      cve: null,
      owasp: ["ASI08"],
      cwe: "CWE-829",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [],
      suppressed: false,
    };
  }

  return {
    rule_id: "mcp-server-config-change",
    finding_id: `CONFIG_CHANGE-${snapshot.serverId}`,
    severity: "HIGH",
    category: "CONFIG_CHANGE",
    layer: "L2",
    file_path: snapshot.configPath,
    location: { field: locationField },
    description: `MCP server "${snapshot.serverId}" configuration has changed since last scan (${previousLastSeen ?? "unknown date"}). Review the changes before proceeding.`,
    affected_tools: ["claude-code", "cursor", "windsurf", "codex-cli", "opencode"],
    cve: null,
    owasp: ["ASI08"],
    cwe: "CWE-829",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    suppressed: false,
  };
}

export function getScanStatePath(customPath?: string): string {
  return resolve(expandHomePath(customPath ?? defaultPath()));
}

export function loadScanState(customPath?: string): ScanState {
  const path = getScanStatePath(customPath);
  if (!existsSync(path)) {
    return { servers: {} };
  }

  let parsed: unknown;
  try {
    const raw = readFileSync(path, "utf8");
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return { servers: {} };
  }
  if (!isRecord(parsed) || !isRecord(parsed.servers)) {
    return { servers: {} };
  }

  const entries: Record<string, ScanStateServerEntry> = {};
  for (const [key, value] of Object.entries(parsed.servers as Record<string, unknown>)) {
    if (!isRecord(value)) {
      continue;
    }
    const config_hash = typeof value.config_hash === "string" ? value.config_hash : "";
    const config_path = typeof value.config_path === "string" ? value.config_path : "";
    const first_seen = typeof value.first_seen === "string" ? value.first_seen : "";
    const last_seen = typeof value.last_seen === "string" ? value.last_seen : "";
    if (!config_hash || !config_path || !first_seen || !last_seen) {
      continue;
    }
    entries[key] = {
      config_hash,
      config_path,
      first_seen,
      last_seen,
    };
  }

  return { servers: entries };
}

export function saveScanState(state: ScanState, customPath?: string): void {
  const path = getScanStatePath(customPath);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, "utf8");
}

export function resetScanState(customPath?: string): void {
  const path = getScanStatePath(customPath);
  rmSync(path, { force: true });
}

export function evaluateScanStateSnapshots(
  input: EvaluateScanStateSnapshotsInput,
): EvaluateScanStateSnapshotsResult {
  const nowIso = input.nowIso ?? new Date().toISOString();
  const nextState: ScanState = {
    servers: { ...input.previousState.servers },
  };
  const findings: Finding[] = [];

  for (const snapshot of input.snapshots) {
    const previous = nextState.servers[snapshot.serverId];
    if (!previous) {
      findings.push(makeStateFinding("NEW_SERVER", snapshot, null));
      nextState.servers[snapshot.serverId] = {
        config_hash: snapshot.configHash,
        config_path: snapshot.configPath,
        first_seen: nowIso,
        last_seen: nowIso,
      };
      continue;
    }

    if (previous.config_hash !== snapshot.configHash) {
      findings.push(makeStateFinding("CONFIG_CHANGE", snapshot, previous.last_seen));
      nextState.servers[snapshot.serverId] = {
        config_hash: snapshot.configHash,
        config_path: snapshot.configPath,
        first_seen: previous.first_seen,
        last_seen: nowIso,
      };
      continue;
    }

    nextState.servers[snapshot.serverId] = {
      ...previous,
      config_path: snapshot.configPath,
      last_seen: nowIso,
    };
  }

  return { findings, nextState };
}

function collectMcpServerRecords(
  value: unknown,
  filePath: string,
  snapshots: McpServerSnapshot[],
): void {
  if (!isRecord(value)) {
    return;
  }

  for (const key of MCP_SERVER_CONTAINER_KEYS) {
    const container = value[key];
    if (!isRecord(container)) {
      continue;
    }

    for (const [serverName, config] of Object.entries(container)) {
      if (!isRecord(config)) {
        continue;
      }
      const commandArray =
        Array.isArray(config.command) && config.command.every((token) => typeof token === "string")
          ? (config.command as string[])
          : null;
      const idFromCommandRaw = commandArray ? extractIdentifierFromCommand(commandArray) : null;
      const idFromCommand = idFromCommandRaw ? normalizeIdentifier(idFromCommandRaw) : null;
      const serverId =
        idFromCommand ??
        (typeof config.url === "string" ? normalizedUrlServerId(config.url) : serverName);
      snapshots.push({
        serverId,
        serverName,
        configHash: sha256(stableStringify(config)),
        configPath: filePath,
        serverPath: `${key}.${serverName}`,
      });
    }
  }

  for (const key of REMOTE_MCP_SERVER_ARRAY_KEYS) {
    const container = value[key];
    if (!Array.isArray(container)) {
      continue;
    }

    container.forEach((config, index) => {
      if (!isRecord(config)) {
        return;
      }

      const serverName =
        typeof config.name === "string" && config.name.trim().length > 0
          ? config.name.trim()
          : `${key}.${index}`;
      const serverId =
        typeof config.url === "string" && config.url.trim().length > 0
          ? normalizedUrlServerId(config.url)
          : `${key}:${serverName}`;

      snapshots.push({
        serverId,
        serverName,
        configHash: sha256(stableStringify(config)),
        configPath: filePath,
        serverPath: `${key}.${index}`,
      });
    });
  }

  for (const child of Object.values(value)) {
    collectMcpServerRecords(child, filePath, snapshots);
  }
}

export function extractMcpServerSnapshots(filePath: string, parsed: unknown): McpServerSnapshot[] {
  const snapshots: McpServerSnapshot[] = [];
  collectMcpServerRecords(parsed, filePath, snapshots);
  return snapshots;
}
