import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { parse as parseJsonc } from "jsonc-parser";
import type { Finding } from "./types/finding.js";
import type { CodeGateReport } from "./types/report.js";
import { applyReportSummary, computeExitCode as computeReportExitCode } from "./report-summary.js";

export const OUTPUT_FORMATS = ["terminal", "json", "sarif", "markdown", "html"] as const;
export type OutputFormat = (typeof OUTPUT_FORMATS)[number];

export const SEVERITY_THRESHOLDS = ["critical", "high", "medium", "low", "info"] as const;
export type SeverityThreshold = (typeof SEVERITY_THRESHOLDS)[number];

export interface TuiConfig {
  enabled: boolean;
  colour_scheme: string;
  compact_mode: boolean;
}

export interface ToolDiscoveryConfig {
  preferred_agent: string;
  agent_paths: Record<string, string>;
  skip_tools: string[];
}

export interface CodeGateConfig {
  severity_threshold: SeverityThreshold;
  auto_proceed_below_threshold: boolean;
  output_format: OutputFormat;
  scan_state_path?: string;
  scan_user_scope?: boolean;
  tui: TuiConfig;
  tool_discovery: ToolDiscoveryConfig;
  trusted_directories: string[];
  blocked_commands: string[];
  known_safe_mcp_servers: string[];
  known_safe_formatters: string[];
  known_safe_lsp_servers: string[];
  known_safe_hooks: string[];
  unicode_analysis: boolean;
  check_ide_settings: boolean;
  owasp_mapping: boolean;
  trusted_api_domains: string[];
  suppress_findings: string[];
}

interface PartialTuiConfig {
  enabled?: boolean;
  colour_scheme?: string;
  compact_mode?: boolean;
}

interface PartialToolDiscoveryConfig {
  preferred_agent?: string;
  agent_paths?: Record<string, string>;
  skip_tools?: string[];
}

interface PartialCodeGateConfig {
  severity_threshold?: string;
  auto_proceed_below_threshold?: boolean;
  output_format?: string;
  scan_state_path?: string;
  scan_user_scope?: boolean;
  tui?: PartialTuiConfig;
  tool_discovery?: PartialToolDiscoveryConfig;
  trusted_directories?: string[];
  blocked_commands?: string[];
  known_safe_mcp_servers?: string[];
  known_safe_formatters?: string[];
  known_safe_lsp_servers?: string[];
  known_safe_hooks?: string[];
  unicode_analysis?: boolean;
  check_ide_settings?: boolean;
  owasp_mapping?: boolean;
  trusted_api_domains?: string[];
  suppress_findings?: string[];
}

export interface CliConfigOverrides {
  format?: OutputFormat;
  configPath?: string;
  noTui?: boolean;
}

export interface ResolveConfigOptions {
  scanTarget: string;
  homeDir?: string;
  cli?: CliConfigOverrides;
}

export const DEFAULT_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: true,
  output_format: "terminal",
  scan_state_path: "~/.codegate/scan-state.json",
  scan_user_scope: true,
  tui: {
    enabled: true,
    colour_scheme: "default",
    compact_mode: false,
  },
  tool_discovery: {
    preferred_agent: "claude",
    agent_paths: {},
    skip_tools: [],
  },
  trusted_directories: [],
  blocked_commands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
  known_safe_mcp_servers: ["@anthropic/mcp-server-filesystem", "@modelcontextprotocol/server-github"],
  known_safe_formatters: ["prettier", "black", "gofmt", "rustfmt", "clang-format"],
  known_safe_lsp_servers: ["typescript-language-server", "pyright", "rust-analyzer", "gopls"],
  known_safe_hooks: [],
  unicode_analysis: true,
  check_ide_settings: true,
  owasp_mapping: true,
  trusted_api_domains: [],
  suppress_findings: [],
};

function normalizeOutputFormat(value: string | undefined): OutputFormat | undefined {
  if (!value) {
    return undefined;
  }
  return OUTPUT_FORMATS.find((format) => format === value) ?? undefined;
}

function normalizeSeverityThreshold(value: string | undefined): SeverityThreshold | undefined {
  if (!value) {
    return undefined;
  }
  return SEVERITY_THRESHOLDS.find((threshold) => threshold === value) ?? undefined;
}

function normalizeOptionalPath(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function unique(values: Array<string[] | undefined>): string[] {
  const merged = values.flatMap((entry) => entry ?? []);
  const seen = new Set<string>();
  const ordered: string[] = [];

  for (const value of merged) {
    if (typeof value !== "string") {
      continue;
    }
    const trimmed = value.trim();
    if (trimmed.length === 0 || seen.has(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    ordered.push(trimmed);
  }

  return ordered;
}

function readConfigFile(path: string): PartialCodeGateConfig {
  if (!existsSync(path)) {
    return {};
  }

  const raw = readFileSync(path, "utf8");
  const parsed = parseJsonc(raw) as unknown;

  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Invalid config file: ${path}`);
  }

  return parsed as PartialCodeGateConfig;
}

function pickFirst<T>(...values: Array<T | undefined>): T | undefined {
  for (const value of values) {
    if (value !== undefined) {
      return value;
    }
  }
  return undefined;
}

export function resolveEffectiveConfig(options: ResolveConfigOptions): CodeGateConfig {
  const home = options.homeDir ?? homedir();
  const scanTarget = resolve(options.scanTarget);
  const globalConfigPath = options.cli?.configPath ?? join(home, ".codegate", "config.json");

  const globalConfig = readConfigFile(globalConfigPath);
  const projectConfig = readConfigFile(join(scanTarget, ".codegate.json"));

  const severity_threshold =
    pickFirst(
      normalizeSeverityThreshold(undefined),
      normalizeSeverityThreshold(projectConfig.severity_threshold),
      normalizeSeverityThreshold(globalConfig.severity_threshold),
      DEFAULT_CONFIG.severity_threshold,
    ) ?? DEFAULT_CONFIG.severity_threshold;

  const output_format =
    pickFirst(
      options.cli?.format,
      normalizeOutputFormat(projectConfig.output_format),
      normalizeOutputFormat(globalConfig.output_format),
      DEFAULT_CONFIG.output_format,
    ) ?? DEFAULT_CONFIG.output_format;

  return {
    severity_threshold,
    auto_proceed_below_threshold:
      pickFirst(
        projectConfig.auto_proceed_below_threshold,
        globalConfig.auto_proceed_below_threshold,
        DEFAULT_CONFIG.auto_proceed_below_threshold,
      ) ?? DEFAULT_CONFIG.auto_proceed_below_threshold,
    output_format,
    scan_state_path:
      pickFirst(
        normalizeOptionalPath(projectConfig.scan_state_path),
        normalizeOptionalPath(globalConfig.scan_state_path),
        normalizeOptionalPath(DEFAULT_CONFIG.scan_state_path),
      ) ?? undefined,
    scan_user_scope:
      pickFirst(projectConfig.scan_user_scope, globalConfig.scan_user_scope, DEFAULT_CONFIG.scan_user_scope) ??
      DEFAULT_CONFIG.scan_user_scope,
    tui: {
      enabled: options.cli?.noTui
        ? false
        : pickFirst(
            projectConfig.tui?.enabled,
            globalConfig.tui?.enabled,
            DEFAULT_CONFIG.tui.enabled,
          ) ?? DEFAULT_CONFIG.tui.enabled,
      colour_scheme:
        pickFirst(
          projectConfig.tui?.colour_scheme,
          globalConfig.tui?.colour_scheme,
          DEFAULT_CONFIG.tui.colour_scheme,
        ) ?? DEFAULT_CONFIG.tui.colour_scheme,
      compact_mode:
        pickFirst(
          projectConfig.tui?.compact_mode,
          globalConfig.tui?.compact_mode,
          DEFAULT_CONFIG.tui.compact_mode,
        ) ?? DEFAULT_CONFIG.tui.compact_mode,
    },
    tool_discovery: {
      preferred_agent:
        pickFirst(
          projectConfig.tool_discovery?.preferred_agent,
          globalConfig.tool_discovery?.preferred_agent,
          DEFAULT_CONFIG.tool_discovery.preferred_agent,
        ) ?? DEFAULT_CONFIG.tool_discovery.preferred_agent,
      agent_paths: {
        ...DEFAULT_CONFIG.tool_discovery.agent_paths,
        ...(globalConfig.tool_discovery?.agent_paths ?? {}),
        ...(projectConfig.tool_discovery?.agent_paths ?? {}),
      },
      skip_tools: unique([
        DEFAULT_CONFIG.tool_discovery.skip_tools,
        globalConfig.tool_discovery?.skip_tools,
        projectConfig.tool_discovery?.skip_tools,
      ]),
    },
    trusted_directories: unique([
      DEFAULT_CONFIG.trusted_directories,
      globalConfig.trusted_directories,
      // Project config cannot set trusted directories.
    ]),
    blocked_commands: unique([
      DEFAULT_CONFIG.blocked_commands,
      globalConfig.blocked_commands,
      projectConfig.blocked_commands,
    ]),
    known_safe_mcp_servers: unique([
      DEFAULT_CONFIG.known_safe_mcp_servers,
      globalConfig.known_safe_mcp_servers,
      projectConfig.known_safe_mcp_servers,
    ]),
    known_safe_formatters: unique([
      DEFAULT_CONFIG.known_safe_formatters,
      globalConfig.known_safe_formatters,
      projectConfig.known_safe_formatters,
    ]),
    known_safe_lsp_servers: unique([
      DEFAULT_CONFIG.known_safe_lsp_servers,
      globalConfig.known_safe_lsp_servers,
      projectConfig.known_safe_lsp_servers,
    ]),
    known_safe_hooks: unique([
      DEFAULT_CONFIG.known_safe_hooks,
      globalConfig.known_safe_hooks,
      projectConfig.known_safe_hooks,
    ]),
    unicode_analysis:
      pickFirst(
        projectConfig.unicode_analysis,
        globalConfig.unicode_analysis,
        DEFAULT_CONFIG.unicode_analysis,
      ) ?? DEFAULT_CONFIG.unicode_analysis,
    check_ide_settings:
      pickFirst(
        projectConfig.check_ide_settings,
        globalConfig.check_ide_settings,
        DEFAULT_CONFIG.check_ide_settings,
      ) ?? DEFAULT_CONFIG.check_ide_settings,
    owasp_mapping:
      pickFirst(projectConfig.owasp_mapping, globalConfig.owasp_mapping, DEFAULT_CONFIG.owasp_mapping) ??
      DEFAULT_CONFIG.owasp_mapping,
    trusted_api_domains: unique([
      DEFAULT_CONFIG.trusted_api_domains,
      globalConfig.trusted_api_domains,
      projectConfig.trusted_api_domains,
    ]),
    suppress_findings: unique([
      DEFAULT_CONFIG.suppress_findings,
      globalConfig.suppress_findings,
      projectConfig.suppress_findings,
    ]),
  };
}

export function computeExitCode(findings: Finding[], threshold: SeverityThreshold): number {
  return computeReportExitCode(findings, threshold);
}

export function applyConfigPolicy(report: CodeGateReport, config: CodeGateConfig): CodeGateReport {
  const suppressionSet = new Set(config.suppress_findings);
  const findings = report.findings.map((finding) => ({
    ...finding,
    owasp: config.owasp_mapping ? finding.owasp : [],
    suppressed: finding.suppressed || suppressionSet.has(finding.finding_id),
  }));

  return applyReportSummary(
    {
      ...report,
      findings,
    },
    config.severity_threshold,
  );
}
