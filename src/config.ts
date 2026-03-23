import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { parse as parseJsonc } from "jsonc-parser";
import type { Finding } from "./types/finding.js";
import type { CodeGateReport } from "./types/report.js";
import { applyReportSummary, computeExitCode as computeReportExitCode } from "./report-summary.js";
import {
  applySuppressionPolicy,
  type RulePolicyConfig,
  type RulePolicyMap,
  type SuppressionRule,
} from "./config/suppression-policy.js";

export const OUTPUT_FORMATS = ["terminal", "json", "sarif", "markdown", "html"] as const;
export type OutputFormat = (typeof OUTPUT_FORMATS)[number];

export const SCAN_COLLECTION_MODES = ["default", "project", "user", "explicit", "all"] as const;
export type ScanCollectionMode = (typeof SCAN_COLLECTION_MODES)[number];

export const SCAN_COLLECTION_KINDS = ["workflows", "actions", "dependabot"] as const;
export type ScanCollectionKind = (typeof SCAN_COLLECTION_KINDS)[number];

export const PERSONAS = ["regular", "pedantic", "auditor"] as const;
export type AuditPersona = (typeof PERSONAS)[number];

export const RUNTIME_MODES = ["offline", "online", "online-no-audits"] as const;
export type RuntimeMode = (typeof RUNTIME_MODES)[number];

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

export interface WorkflowAuditConfig {
  enabled: boolean;
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
  rule_pack_paths?: string[];
  allowed_rules?: string[];
  skip_rules?: string[];
  strict_collection?: boolean;
  scan_collection_modes?: ScanCollectionMode[];
  scan_collection_kinds?: ScanCollectionKind[];
  rules?: RulePolicyMap;
  persona?: AuditPersona;
  runtime_mode?: RuntimeMode;
  workflow_audits?: WorkflowAuditConfig;
  suppress_findings: string[];
  suppression_rules?: SuppressionRule[];
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
  rule_pack_paths?: string[];
  allowed_rules?: string[];
  skip_rules?: string[];
  strict_collection?: boolean;
  scan_collection_modes?: string[];
  scan_collection_kinds?: string[];
  rules?: Record<string, PartialRulePolicyConfig>;
  persona?: string;
  runtime_mode?: string;
  workflow_audits?: {
    enabled?: boolean;
  };
  suppress_findings?: string[];
  suppression_rules?: SuppressionRule[];
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
  known_safe_mcp_servers: [
    "@anthropic/mcp-server-filesystem",
    "@modelcontextprotocol/server-github",
  ],
  known_safe_formatters: ["prettier", "black", "gofmt", "rustfmt", "clang-format"],
  known_safe_lsp_servers: ["typescript-language-server", "pyright", "rust-analyzer", "gopls"],
  known_safe_hooks: [],
  unicode_analysis: true,
  check_ide_settings: true,
  owasp_mapping: true,
  trusted_api_domains: [],
  rule_pack_paths: [],
  allowed_rules: [],
  skip_rules: [],
  strict_collection: false,
  scan_collection_modes: ["default"],
  persona: "regular",
  runtime_mode: "offline",
  workflow_audits: { enabled: false },
  suppress_findings: [],
  suppression_rules: [],
};

interface PartialRulePolicyConfig {
  disable?: boolean;
  ignore?: string[];
  config?: Record<string, unknown>;
}

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

function normalizeCollectionMode(value: string | undefined): ScanCollectionMode | undefined {
  if (!value) {
    return undefined;
  }
  return SCAN_COLLECTION_MODES.find((mode) => mode === value) ?? undefined;
}

function normalizeCollectionModes(values: string[] | undefined): ScanCollectionMode[] | undefined {
  if (!values) {
    return undefined;
  }

  const normalized: ScanCollectionMode[] = [];
  for (const value of values) {
    const mode = normalizeCollectionMode(value);
    if (!mode || normalized.includes(mode)) {
      continue;
    }
    normalized.push(mode);
  }

  return normalized.length > 0 ? normalized : undefined;
}

function normalizeCollectionKind(value: string | undefined): ScanCollectionKind | undefined {
  if (!value) {
    return undefined;
  }
  return SCAN_COLLECTION_KINDS.find((kind) => kind === value) ?? undefined;
}

function normalizeCollectionKinds(values: string[] | undefined): ScanCollectionKind[] | undefined {
  if (!values) {
    return undefined;
  }

  const normalized: ScanCollectionKind[] = [];
  for (const value of values) {
    const kind = normalizeCollectionKind(value);
    if (!kind || normalized.includes(kind)) {
      continue;
    }
    normalized.push(kind);
  }

  return normalized.length > 0 ? normalized : undefined;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function normalizeRulePolicyConfig(value: unknown): RulePolicyConfig | undefined {
  if (!isPlainObject(value)) {
    return undefined;
  }

  const disable = typeof value.disable === "boolean" ? value.disable : undefined;
  const ignoreRaw = value.ignore;
  const ignore =
    Array.isArray(ignoreRaw) && ignoreRaw.length > 0
      ? ignoreRaw
          .filter((entry): entry is string => typeof entry === "string")
          .map((entry) => entry.trim())
          .filter((entry) => entry.length > 0)
      : undefined;
  const configRaw = value.config;
  const config = isPlainObject(configRaw) ? { ...configRaw } : undefined;

  if (disable === undefined && ignore === undefined && config === undefined) {
    return undefined;
  }

  return {
    disable,
    ignore,
    config,
  };
}

function normalizeRulePolicyMap(
  rules: Record<string, PartialRulePolicyConfig> | undefined,
): RulePolicyMap | undefined {
  if (!rules || typeof rules !== "object") {
    return undefined;
  }

  const normalized: RulePolicyMap = {};

  for (const [ruleId, value] of Object.entries(rules)) {
    const key = ruleId.trim();
    if (key.length === 0) {
      continue;
    }

    const policy = normalizeRulePolicyConfig(value);
    if (!policy) {
      continue;
    }

    normalized[key] = policy;
  }

  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

function mergeRulePolicyConfig(
  current: RulePolicyConfig | undefined,
  incoming: RulePolicyConfig | undefined,
): RulePolicyConfig | undefined {
  if (!current) {
    if (!incoming) {
      return undefined;
    }
    return {
      disable: incoming.disable,
      ignore: incoming.ignore ? [...incoming.ignore] : undefined,
      config: incoming.config ? { ...incoming.config } : undefined,
    };
  }

  if (!incoming) {
    return {
      disable: current.disable,
      ignore: current.ignore ? [...current.ignore] : undefined,
      config: current.config ? { ...current.config } : undefined,
    };
  }

  return {
    disable: incoming.disable ?? current.disable,
    ignore: unique([
      current.ignore as string[] | undefined,
      incoming.ignore as string[] | undefined,
    ]),
    config:
      current.config || incoming.config
        ? {
            ...(current.config ?? {}),
            ...(incoming.config ?? {}),
          }
        : undefined,
  };
}

function mergeRulePolicyMaps(...maps: Array<RulePolicyMap | undefined>): RulePolicyMap | undefined {
  const merged: RulePolicyMap = {};

  for (const map of maps) {
    if (!map) {
      continue;
    }
    for (const [ruleId, policy] of Object.entries(map)) {
      merged[ruleId] = mergeRulePolicyConfig(merged[ruleId], policy) ?? merged[ruleId];
    }
  }

  return Object.keys(merged).length > 0 ? merged : undefined;
}

function normalizePersona(value: string | undefined): AuditPersona | undefined {
  if (!value) {
    return undefined;
  }
  return PERSONAS.find((persona) => persona === value) ?? undefined;
}

function normalizeRuntimeMode(value: string | undefined): RuntimeMode | undefined {
  if (!value) {
    return undefined;
  }
  return RUNTIME_MODES.find((mode) => mode === value) ?? undefined;
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
      pickFirst(
        projectConfig.scan_user_scope,
        globalConfig.scan_user_scope,
        DEFAULT_CONFIG.scan_user_scope,
      ) ?? DEFAULT_CONFIG.scan_user_scope,
    tui: {
      enabled: options.cli?.noTui
        ? false
        : (pickFirst(
            projectConfig.tui?.enabled,
            globalConfig.tui?.enabled,
            DEFAULT_CONFIG.tui.enabled,
          ) ?? DEFAULT_CONFIG.tui.enabled),
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
      pickFirst(
        projectConfig.owasp_mapping,
        globalConfig.owasp_mapping,
        DEFAULT_CONFIG.owasp_mapping,
      ) ?? DEFAULT_CONFIG.owasp_mapping,
    trusted_api_domains: unique([
      DEFAULT_CONFIG.trusted_api_domains,
      globalConfig.trusted_api_domains,
      projectConfig.trusted_api_domains,
    ]),
    rule_pack_paths: unique([
      DEFAULT_CONFIG.rule_pack_paths,
      globalConfig.rule_pack_paths,
      projectConfig.rule_pack_paths,
    ]),
    allowed_rules: unique([
      DEFAULT_CONFIG.allowed_rules,
      globalConfig.allowed_rules,
      projectConfig.allowed_rules,
    ]),
    skip_rules: unique([
      DEFAULT_CONFIG.skip_rules,
      globalConfig.skip_rules,
      projectConfig.skip_rules,
    ]),
    strict_collection:
      pickFirst(
        projectConfig.strict_collection,
        globalConfig.strict_collection,
        DEFAULT_CONFIG.strict_collection,
      ) ?? DEFAULT_CONFIG.strict_collection,
    scan_collection_modes:
      pickFirst(
        normalizeCollectionModes(projectConfig.scan_collection_modes),
        normalizeCollectionModes(globalConfig.scan_collection_modes),
        DEFAULT_CONFIG.scan_collection_modes,
      ) ?? DEFAULT_CONFIG.scan_collection_modes,
    scan_collection_kinds:
      pickFirst(
        normalizeCollectionKinds(projectConfig.scan_collection_kinds),
        normalizeCollectionKinds(globalConfig.scan_collection_kinds),
      ) ?? undefined,
    rules:
      mergeRulePolicyMaps(
        normalizeRulePolicyMap(globalConfig.rules),
        normalizeRulePolicyMap(projectConfig.rules),
      ) ?? undefined,
    persona:
      pickFirst(
        normalizePersona(projectConfig.persona),
        normalizePersona(globalConfig.persona),
        DEFAULT_CONFIG.persona,
      ) ?? DEFAULT_CONFIG.persona,
    runtime_mode:
      pickFirst(
        normalizeRuntimeMode(projectConfig.runtime_mode),
        normalizeRuntimeMode(globalConfig.runtime_mode),
        DEFAULT_CONFIG.runtime_mode,
      ) ?? DEFAULT_CONFIG.runtime_mode,
    workflow_audits: {
      enabled:
        pickFirst(
          projectConfig.workflow_audits?.enabled,
          globalConfig.workflow_audits?.enabled,
          DEFAULT_CONFIG.workflow_audits?.enabled,
        ) ?? false,
    },
    suppress_findings: unique([
      DEFAULT_CONFIG.suppress_findings,
      globalConfig.suppress_findings,
      projectConfig.suppress_findings,
    ]),
    suppression_rules: [
      ...(DEFAULT_CONFIG.suppression_rules ?? []),
      ...(globalConfig.suppression_rules ?? []),
      ...(projectConfig.suppression_rules ?? []),
    ],
  };
}

export function computeExitCode(findings: Finding[], threshold: SeverityThreshold): number {
  return computeReportExitCode(findings, threshold);
}

export function applyConfigPolicy(report: CodeGateReport, config: CodeGateConfig): CodeGateReport {
  const findings = applySuppressionPolicy(report.findings, {
    suppress_findings: config.suppress_findings,
    suppression_rules: config.suppression_rules,
    rule_policies: config.rules,
  }).map((finding) => ({
    ...finding,
    owasp: config.owasp_mapping ? finding.owasp : [],
  }));

  return applyReportSummary(
    {
      ...report,
      findings,
    },
    config.severity_threshold,
  );
}
