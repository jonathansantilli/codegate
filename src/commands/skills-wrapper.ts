import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { resolve } from "node:path";
import {
  PERSONAS,
  RUNTIME_MODES,
  SCAN_COLLECTION_KINDS,
  SCAN_COLLECTION_MODES,
  OUTPUT_FORMATS,
  type AuditPersona,
  type CliConfigOverrides,
  type CodeGateConfig,
  type OutputFormat,
  type ResolveConfigOptions,
  type RuntimeMode,
  type ScanCollectionKind,
  type ScanCollectionMode,
} from "../config.js";
import { renderByFormat, summarizeRequestedTargetFindings } from "./scan-command/helpers.js";
import { resolveScanTarget, type ResolvedScanTarget } from "../scan-target.js";
import { runScanAnalysis, type ScanAnalysisDeps, type ScanRunnerInput } from "./scan-command.js";
import type { CodeGateReport } from "../types/report.js";

export interface SkillsWrapperRuntimeOptions {
  force: boolean;
  deep: boolean;
  noTui: boolean;
  verbose: boolean;
  includeUserScope: boolean;
  strictCollection: boolean;
  workflowAudits: boolean;
  collect: ScanCollectionMode[];
  collectKinds: ScanCollectionKind[];
  persona?: AuditPersona;
  runtimeMode?: RuntimeMode;
  format?: OutputFormat;
  configPath?: string;
}

export interface ParsedSkillsInvocation {
  passthroughArgs: string[];
  wrapper: SkillsWrapperRuntimeOptions;
  subcommand: string | null;
  sourceTarget: string | null;
  preferredSkill: string | null;
}

export interface SkillsWrapperLaunchResult {
  status: number | null;
  error?: Error;
}

export interface ExecuteSkillsWrapperInput {
  version: string;
  skillsArgs: string[];
}

export interface SkillsWarningConsentContext {
  target: string;
  report: CodeGateReport;
}

export interface SkillsWrapperDeps {
  cwd: () => string;
  isTTY: () => boolean;
  pathExists?: (path: string) => boolean;
  resolveConfig: (options: ResolveConfigOptions) => CodeGateConfig;
  runScan: (input: ScanRunnerInput) => Promise<CodeGateReport>;
  prepareScanDiscovery?: ScanAnalysisDeps["prepareScanDiscovery"];
  discoverDeepResources?: ScanAnalysisDeps["discoverDeepResources"];
  discoverLocalTextTargets?: ScanAnalysisDeps["discoverLocalTextTargets"];
  requestDeepScanConsent?: ScanAnalysisDeps["requestDeepScanConsent"];
  requestDeepAgentSelection?: ScanAnalysisDeps["requestDeepAgentSelection"];
  requestMetaAgentCommandConsent?: ScanAnalysisDeps["requestMetaAgentCommandConsent"];
  runMetaAgentCommand?: ScanAnalysisDeps["runMetaAgentCommand"];
  executeDeepResource?: ScanAnalysisDeps["executeDeepResource"];
  resolveScanTarget?: (input: {
    rawTarget: string;
    cwd: string;
    preferredSkill?: string;
    interactive?: boolean;
    requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
  }) => Promise<ResolvedScanTarget> | ResolvedScanTarget;
  requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
  requestWarningProceed?: (context: SkillsWarningConsentContext) => Promise<boolean> | boolean;
  launchSkills: (args: string[], cwd: string) => SkillsWrapperLaunchResult;
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  setExitCode: (code: number) => void;
  renderTui?: (props: {
    view: "dashboard" | "summary";
    report: CodeGateReport;
    notices?: string[];
  }) => void;
}

interface SourceDetectionContext {
  cwd: string;
  pathExists: (path: string) => boolean;
}

function parseWrapperOptionValue(args: string[], index: number, flag: string): [string, number] {
  const current = args[index] ?? "";
  const withEquals = `${flag}=`;
  if (current.startsWith(withEquals)) {
    const value = current.slice(withEquals.length).trim();
    if (value.length === 0) {
      throw new Error(`${flag} requires a value`);
    }
    return [value, index];
  }

  const nextValue = args[index + 1];
  if (
    !nextValue ||
    nextValue.trim().length === 0 ||
    nextValue === "--" ||
    nextValue.startsWith("-")
  ) {
    throw new Error(`${flag} requires a value`);
  }

  return [nextValue, index + 1];
}

function parseOutputFormat(value: string): OutputFormat {
  const normalized = value.trim().toLowerCase();
  const matched = OUTPUT_FORMATS.find((format) => format === normalized);
  if (!matched) {
    throw new Error(
      `Unsupported --cg-format value "${value}". Valid values: ${OUTPUT_FORMATS.join(", ")}.`,
    );
  }
  return matched;
}

function parseCollectionMode(value: string): ScanCollectionMode {
  const normalized = value.trim().toLowerCase();
  const matched = SCAN_COLLECTION_MODES.find((mode) => mode === normalized);
  if (!matched) {
    throw new Error(
      `Unsupported --cg-collect value "${value}". Valid values: ${SCAN_COLLECTION_MODES.join(", ")}.`,
    );
  }
  return matched;
}

function parseCollectionKind(value: string): ScanCollectionKind {
  const normalized = value.trim().toLowerCase();
  const matched = SCAN_COLLECTION_KINDS.find((kind) => kind === normalized);
  if (!matched) {
    throw new Error(
      `Unsupported --cg-collect-kind value "${value}". Valid values: ${SCAN_COLLECTION_KINDS.join(", ")}.`,
    );
  }
  return matched;
}

function parsePersona(value: string): AuditPersona {
  const normalized = value.trim().toLowerCase();
  const matched = PERSONAS.find((persona) => persona === normalized);
  if (!matched) {
    throw new Error(
      `Unsupported --cg-persona value "${value}". Valid values: ${PERSONAS.join(", ")}.`,
    );
  }
  return matched;
}

function parseRuntimeMode(value: string): RuntimeMode {
  const normalized = value.trim().toLowerCase();
  const matched = RUNTIME_MODES.find((mode) => mode === normalized);
  if (!matched) {
    throw new Error(
      `Unsupported --cg-runtime-mode value "${value}". Valid values: ${RUNTIME_MODES.join(", ")}.`,
    );
  }
  return matched;
}

function isLikelyGitSshSource(value: string): boolean {
  return /^git@[^:]+:.+/iu.test(value) || /^ssh:\/\//iu.test(value);
}

function looksLikeSourceToken(value: string, context?: SourceDetectionContext): boolean {
  if (value.trim().length === 0 || value.startsWith("-")) {
    return false;
  }
  if (isLikelyHttpUrl(value) || isLikelyGitSshSource(value) || isLikelyGitHubShorthand(value)) {
    return true;
  }
  if (
    value.startsWith("./") ||
    value.startsWith("../") ||
    value.startsWith("/") ||
    value.startsWith("~/") ||
    value.endsWith(".git")
  ) {
    return true;
  }

  if (context) {
    const localCandidate = resolve(context.cwd, value);
    if (context.pathExists(localCandidate)) {
      return true;
    }
  }

  return false;
}

function firstLikelySourceAfterAdd(
  args: string[],
  addIndex: number,
  context?: SourceDetectionContext,
): string | null {
  for (let index = addIndex + 1; index < args.length; index += 1) {
    const token = args[index] ?? "";
    if (token === "--skill") {
      index += 1;
      continue;
    }
    if (token.startsWith("--skill=")) {
      continue;
    }
    if (token === "--") {
      for (let tailIndex = index + 1; tailIndex < args.length; tailIndex += 1) {
        const candidate = args[tailIndex] ?? "";
        if (looksLikeSourceToken(candidate, context)) {
          return candidate;
        }
      }
      return null;
    }
    if (looksLikeSourceToken(token, context)) {
      // Heuristic: if a source-looking token is immediately after an option flag and followed by
      // another source-looking token, treat the first one as an option value and continue.
      const previous = index > addIndex + 1 ? (args[index - 1] ?? "") : "";
      const next = args[index + 1] ?? "";
      if (
        previous.startsWith("-") &&
        !previous.startsWith("--skill") &&
        looksLikeSourceToken(next, context)
      ) {
        continue;
      }
      return token;
    }
  }

  return null;
}

function preferredSkillArg(args: string[], addIndex: number): string | null {
  for (let index = addIndex + 1; index < args.length; index += 1) {
    const token = args[index] ?? "";
    if (token === "--skill") {
      const value = args[index + 1];
      if (value && value.trim().length > 0) {
        return value.trim();
      }
      return null;
    }
    if (token.startsWith("--skill=")) {
      const value = token.slice("--skill=".length).trim();
      return value.length > 0 ? value : null;
    }
  }
  return null;
}

function isLikelyHttpUrl(value: string): boolean {
  return /^https?:\/\//iu.test(value);
}

function isLikelyGitHubShorthand(value: string): boolean {
  return /^[a-z0-9._-]+\/[a-z0-9._-]+(?:\.git)?$/iu.test(value);
}

function normalizeSkillsSourceTarget(
  rawTarget: string,
  cwd: string,
  pathExists: (path: string) => boolean,
): string {
  if (isLikelyHttpUrl(rawTarget)) {
    return rawTarget;
  }

  if (!isLikelyGitHubShorthand(rawTarget)) {
    return rawTarget;
  }

  const localCandidate = resolve(cwd, rawTarget);
  if (pathExists(localCandidate)) {
    return rawTarget;
  }

  return `https://github.com/${rawTarget}`;
}

function toSubcommand(args: string[]): [string | null, number] {
  const index = args.findIndex((value) => !value.startsWith("-"));
  if (index < 0) {
    return [null, -1];
  }
  return [args[index]?.toLowerCase() ?? null, index];
}

function isLikelyLeadingGlobalOptionSequence(args: string[], endExclusive: number): boolean {
  for (let index = 0; index < endExclusive; index += 1) {
    const token = args[index] ?? "";
    if (token.startsWith("-")) {
      continue;
    }
    const previous = index > 0 ? (args[index - 1] ?? "") : "";
    if (previous.startsWith("-")) {
      continue;
    }
    return false;
  }

  return true;
}

function findAddSubcommandIndex(args: string[], context?: SourceDetectionContext): number {
  const [subcommand, subcommandIndex] = toSubcommand(args);
  if (subcommand === "add") {
    return subcommandIndex;
  }

  // Only attempt fallback when the first positional token is likely an option value.
  // This avoids misclassifying non-add commands like `skills find add`.
  if (
    subcommandIndex < 1 ||
    typeof args[subcommandIndex - 1] !== "string" ||
    !String(args[subcommandIndex - 1]).startsWith("-")
  ) {
    return -1;
  }

  // Fallback for inputs where global-option values appear before `add`.
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index]?.toLowerCase();
    if (token !== "add") {
      continue;
    }
    if (
      isLikelyLeadingGlobalOptionSequence(args, index) &&
      firstLikelySourceAfterAdd(args, index, context)
    ) {
      return index;
    }
  }

  return -1;
}

export function parseSkillsInvocation(
  rawArgs: string[],
  context?: SourceDetectionContext,
): ParsedSkillsInvocation {
  const wrapper: SkillsWrapperRuntimeOptions = {
    force: false,
    deep: false,
    noTui: false,
    verbose: false,
    includeUserScope: false,
    strictCollection: false,
    workflowAudits: false,
    collect: [],
    collectKinds: [],
    persona: undefined,
    runtimeMode: undefined,
    format: undefined,
    configPath: undefined,
  };
  const passthroughArgs: string[] = [];

  for (let index = 0; index < rawArgs.length; index += 1) {
    const token = rawArgs[index] ?? "";
    if (token === "--") {
      passthroughArgs.push("--");
      for (let tailIndex = index + 1; tailIndex < rawArgs.length; tailIndex += 1) {
        passthroughArgs.push(rawArgs[tailIndex] ?? "");
      }
      break;
    }
    if (token === "--cg-force") {
      wrapper.force = true;
      continue;
    }
    if (token === "--cg-deep") {
      wrapper.deep = true;
      continue;
    }
    if (token === "--cg-no-tui") {
      wrapper.noTui = true;
      continue;
    }
    if (token === "--cg-verbose") {
      wrapper.verbose = true;
      continue;
    }
    if (token === "--cg-include-user-scope") {
      wrapper.includeUserScope = true;
      continue;
    }
    if (token === "--cg-strict-collection") {
      wrapper.strictCollection = true;
      continue;
    }
    if (token === "--cg-workflow-audits") {
      wrapper.workflowAudits = true;
      continue;
    }
    if (token === "--cg-format" || token.startsWith("--cg-format=")) {
      const [value, consumedIndex] = parseWrapperOptionValue(rawArgs, index, "--cg-format");
      wrapper.format = parseOutputFormat(value);
      index = consumedIndex;
      continue;
    }
    if (token === "--cg-config" || token.startsWith("--cg-config=")) {
      const [value, consumedIndex] = parseWrapperOptionValue(rawArgs, index, "--cg-config");
      wrapper.configPath = value;
      index = consumedIndex;
      continue;
    }
    if (token === "--cg-collect" || token.startsWith("--cg-collect=")) {
      const [value, consumedIndex] = parseWrapperOptionValue(rawArgs, index, "--cg-collect");
      const mode = parseCollectionMode(value);
      if (!wrapper.collect.includes(mode)) {
        wrapper.collect.push(mode);
      }
      index = consumedIndex;
      continue;
    }
    if (token === "--cg-collect-kind" || token.startsWith("--cg-collect-kind=")) {
      const [value, consumedIndex] = parseWrapperOptionValue(rawArgs, index, "--cg-collect-kind");
      const kind = parseCollectionKind(value);
      if (!wrapper.collectKinds.includes(kind)) {
        wrapper.collectKinds.push(kind);
      }
      index = consumedIndex;
      continue;
    }
    if (token === "--cg-persona" || token.startsWith("--cg-persona=")) {
      const [value, consumedIndex] = parseWrapperOptionValue(rawArgs, index, "--cg-persona");
      wrapper.persona = parsePersona(value);
      index = consumedIndex;
      continue;
    }
    if (token === "--cg-runtime-mode" || token.startsWith("--cg-runtime-mode=")) {
      const [value, consumedIndex] = parseWrapperOptionValue(rawArgs, index, "--cg-runtime-mode");
      wrapper.runtimeMode = parseRuntimeMode(value);
      index = consumedIndex;
      continue;
    }
    if (token.startsWith("--cg-")) {
      throw new Error(`Unknown CodeGate wrapper option: ${token}`);
    }

    passthroughArgs.push(token);
  }

  const addSubcommandIndex = findAddSubcommandIndex(passthroughArgs, context);
  const subcommand = addSubcommandIndex >= 0 ? "add" : toSubcommand(passthroughArgs)[0];
  const sourceTarget =
    addSubcommandIndex >= 0
      ? firstLikelySourceAfterAdd(passthroughArgs, addSubcommandIndex, context)
      : null;
  const preferredSkill =
    addSubcommandIndex >= 0 ? preferredSkillArg(passthroughArgs, addSubcommandIndex) : null;

  return {
    passthroughArgs,
    wrapper,
    subcommand,
    sourceTarget,
    preferredSkill,
  };
}

async function promptWarningProceed(context: SkillsWarningConsentContext): Promise<boolean> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  const prompt = [
    `Warning findings detected for ${context.target}.`,
    `Findings: ${context.report.summary.total}`,
    "Proceed with skills install? [y/N]: ",
  ].join("\n");

  try {
    const answer = await rl.question(prompt);
    return /^y(es)?$/iu.test(answer.trim());
  } finally {
    rl.close();
  }
}

function finalizeLaunch(result: SkillsWrapperLaunchResult, deps: SkillsWrapperDeps): void {
  if (result.error) {
    deps.stderr(`Failed to run npx skills: ${result.error.message}`);
    deps.setExitCode(3);
    return;
  }
  deps.setExitCode(result.status ?? 1);
}

function shouldPromptForWarning(
  report: CodeGateReport,
  config: CodeGateConfig,
  force: boolean,
): boolean {
  return (
    report.summary.exit_code === 1 &&
    report.findings.length > 0 &&
    force !== true &&
    config.auto_proceed_below_threshold !== true
  );
}

export function launchSkillsPassthrough(args: string[], cwd: string): SkillsWrapperLaunchResult {
  const result = spawnSync("npx", ["skills", ...args], {
    cwd,
    stdio: "inherit",
  });
  return {
    status: result.status,
    error: result.error ?? undefined,
  };
}

export async function executeSkillsWrapper(
  input: ExecuteSkillsWrapperInput,
  deps: SkillsWrapperDeps,
): Promise<void> {
  const cwd = deps.cwd();
  const isTTY = deps.isTTY();
  const pathExists = deps.pathExists ?? ((path: string) => existsSync(path));
  const sourceDetectionContext: SourceDetectionContext = { cwd, pathExists };
  const parsed = parseSkillsInvocation(input.skillsArgs, sourceDetectionContext);

  if (parsed.subcommand !== "add") {
    finalizeLaunch(deps.launchSkills(parsed.passthroughArgs, cwd), deps);
    return;
  }

  const resolvedSourceTarget = parsed.sourceTarget;
  const preferredSkill = parsed.preferredSkill ?? undefined;

  if (!resolvedSourceTarget) {
    deps.stderr(
      "Could not determine the source target for `skills add`. Provide a source URL/path after `add`.",
    );
    deps.setExitCode(3);
    return;
  }

  let resolvedTarget: ResolvedScanTarget | undefined;
  const interactivePromptsEnabled = isTTY && parsed.wrapper.noTui !== true;

  try {
    const sourceTarget = normalizeSkillsSourceTarget(resolvedSourceTarget, cwd, pathExists);
    const resolveTarget =
      deps.resolveScanTarget ??
      ((resolverInput: {
        rawTarget: string;
        cwd: string;
        preferredSkill?: string;
        interactive?: boolean;
        requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
      }) => resolveScanTarget(resolverInput));
    resolvedTarget = await resolveTarget({
      rawTarget: sourceTarget,
      cwd,
      preferredSkill,
      interactive: interactivePromptsEnabled,
      requestSkillSelection: interactivePromptsEnabled ? deps.requestSkillSelection : undefined,
    });

    const noTui = parsed.wrapper.noTui === true || !isTTY;
    const cliConfig: CliConfigOverrides = {
      format: parsed.wrapper.format,
      configPath: parsed.wrapper.configPath,
      noTui,
    };
    const baseConfig = deps.resolveConfig({
      scanTarget: resolvedTarget.scanTarget,
      cli: cliConfig,
    });
    const config: CodeGateConfig = {
      ...baseConfig,
      scan_user_scope:
        parsed.wrapper.includeUserScope === true ? true : (baseConfig.scan_user_scope ?? false),
      scan_collection_modes:
        parsed.wrapper.collect.length > 0
          ? parsed.wrapper.collect
          : baseConfig.scan_collection_modes,
      scan_collection_kinds:
        parsed.wrapper.collectKinds.length > 0
          ? parsed.wrapper.collectKinds
          : baseConfig.scan_collection_kinds,
      strict_collection:
        parsed.wrapper.strictCollection === true ? true : (baseConfig.strict_collection ?? false),
      persona: parsed.wrapper.persona ?? baseConfig.persona,
      runtime_mode: parsed.wrapper.runtimeMode ?? baseConfig.runtime_mode,
      workflow_audits: {
        enabled:
          parsed.wrapper.workflowAudits === true
            ? true
            : (baseConfig.workflow_audits?.enabled ?? false),
      },
    };

    const { report, deepScanNotes } = await runScanAnalysis(
      {
        version: input.version,
        scanTarget: resolvedTarget.scanTarget,
        displayTarget: resolvedTarget.displayTarget,
        explicitCandidates: resolvedTarget.explicitCandidates,
        config,
        options: {
          noTui,
          format: parsed.wrapper.format,
          verbose: parsed.wrapper.verbose,
          force: parsed.wrapper.force,
          includeUserScope: parsed.wrapper.includeUserScope,
          collect: parsed.wrapper.collect.length > 0 ? parsed.wrapper.collect : undefined,
          strictCollection: parsed.wrapper.strictCollection,
          persona: parsed.wrapper.persona,
          runtimeMode: parsed.wrapper.runtimeMode,
          workflowAudits: parsed.wrapper.workflowAudits,
          skill: preferredSkill,
          deep: parsed.wrapper.deep,
        },
      },
      {
        isTTY: deps.isTTY,
        runScan: deps.runScan,
        prepareScanDiscovery: deps.prepareScanDiscovery,
        discoverDeepResources: deps.discoverDeepResources,
        discoverLocalTextTargets: deps.discoverLocalTextTargets,
        requestDeepScanConsent: interactivePromptsEnabled ? deps.requestDeepScanConsent : undefined,
        requestDeepAgentSelection: interactivePromptsEnabled
          ? deps.requestDeepAgentSelection
          : undefined,
        requestMetaAgentCommandConsent: interactivePromptsEnabled
          ? deps.requestMetaAgentCommandConsent
          : undefined,
        runMetaAgentCommand: deps.runMetaAgentCommand,
        executeDeepResource: deps.executeDeepResource,
      },
    );

    const shouldUseTui =
      config.tui.enabled && isTTY && deps.renderTui !== undefined && noTui !== true;
    const targetSummaryNote =
      config.output_format === "terminal"
        ? summarizeRequestedTargetFindings(report, resolvedTarget.displayTarget)
        : null;
    const scanNotes =
      config.output_format === "terminal"
        ? targetSummaryNote
          ? [...deepScanNotes, targetSummaryNote]
          : deepScanNotes
        : [];
    if (shouldUseTui) {
      deps.renderTui?.({
        view: "dashboard",
        report,
        notices: scanNotes.length > 0 ? scanNotes : undefined,
      });
      deps.renderTui?.({ view: "summary", report });
    } else {
      for (const note of scanNotes) {
        deps.stdout(note);
      }
      deps.stdout(renderByFormat(config.output_format, report));
    }

    if (report.summary.exit_code === 2 && parsed.wrapper.force !== true) {
      deps.stderr("Dangerous findings detected. Aborting `skills add` (fail-closed).");
      deps.setExitCode(2);
      return;
    }

    if (shouldPromptForWarning(report, config, parsed.wrapper.force)) {
      if (!interactivePromptsEnabled) {
        deps.stderr(
          "Warning findings detected. Aborting `skills add` in non-interactive mode (fail-closed). Use --cg-force to override.",
        );
        deps.setExitCode(1);
        return;
      }

      const requestProceed = deps.requestWarningProceed ?? promptWarningProceed;
      const approved = await requestProceed({
        target: resolvedSourceTarget,
        report,
      });
      if (!approved) {
        deps.stderr("Install cancelled by user.");
        deps.setExitCode(1);
        return;
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (parsed.wrapper.force !== true) {
      deps.stderr(`Preflight scan failed (fail-closed): ${message}`);
      deps.setExitCode(3);
      return;
    }

    deps.stderr(`Preflight scan failed, continuing due to --cg-force: ${message}`);
  } finally {
    if (resolvedTarget?.cleanup) {
      try {
        await resolvedTarget.cleanup();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        deps.stderr(`Scan target cleanup failed: ${message}`);
      }
    }
  }

  finalizeLaunch(deps.launchSkills(parsed.passthroughArgs, cwd), deps);
}
