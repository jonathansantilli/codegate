import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import {
  applyConfigPolicy,
  OUTPUT_FORMATS,
  type CliConfigOverrides,
  type CodeGateConfig,
  type OutputFormat,
  type ResolveConfigOptions,
} from "../config.js";
import { reorderRequestedTargetFindings } from "../report/requested-target-findings.js";
import { resolveScanTarget, type ResolvedScanTarget } from "../scan-target.js";
import type { CodeGateReport } from "../types/report.js";
import type { ScanRunnerInput } from "./scan-command.js";
import { renderByFormat, summarizeRequestedTargetFindings } from "./scan-command/helpers.js";

const CLAWHUB_GLOBAL_OPTIONS_WITH_VALUE = new Set(["--workdir", "--dir", "--site", "--registry"]);
const CLAWHUB_INSTALL_OPTIONS_WITH_VALUE = new Set(["--version"]);
const NPX_CLAWHUB_BASE_ARGS = ["--yes", "clawhub"] as const;

interface SourceDetectionContext {
  cwd: string;
  pathExists: (path: string) => boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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

function isLikelyHttpUrl(value: string): boolean {
  return /^https?:\/\//iu.test(value);
}

function splitLongOption(token: string): [string, string | null] {
  const equalsIndex = token.indexOf("=");
  if (equalsIndex < 0) {
    return [token, null];
  }
  return [token.slice(0, equalsIndex), token.slice(equalsIndex + 1)];
}

function isValueOption(flag: string): boolean {
  return (
    CLAWHUB_GLOBAL_OPTIONS_WITH_VALUE.has(flag) || CLAWHUB_INSTALL_OPTIONS_WITH_VALUE.has(flag)
  );
}

function firstPositionalToken(args: string[]): [string | null, number] {
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index] ?? "";
    if (token === "--") {
      return [null, -1];
    }

    if (token.startsWith("--")) {
      const [flag, inlineValue] = splitLongOption(token);
      if (inlineValue === null && isValueOption(flag)) {
        index += 1;
      }
      continue;
    }

    if (token.startsWith("-")) {
      continue;
    }

    return [token.toLowerCase(), index];
  }

  return [null, -1];
}

function isLikelyLeadingGlobalOptionSequence(args: string[], endExclusive: number): boolean {
  for (let index = 0; index < endExclusive; index += 1) {
    const token = args[index] ?? "";
    if (token === "--") {
      return false;
    }

    if (token.startsWith("--")) {
      const [flag, inlineValue] = splitLongOption(token);
      if (inlineValue === null && isValueOption(flag)) {
        index += 1;
      }
      continue;
    }

    if (token.startsWith("-")) {
      continue;
    }

    return false;
  }

  return true;
}

function looksLikeSourceToken(value: string, context?: SourceDetectionContext): boolean {
  if (value.trim().length === 0 || value.startsWith("-")) {
    return false;
  }

  if (
    isLikelyHttpUrl(value) ||
    value.startsWith("./") ||
    value.startsWith("../") ||
    value.startsWith("/") ||
    value.startsWith("~/") ||
    value.startsWith("~\\")
  ) {
    return true;
  }

  if (context) {
    const localCandidate = resolve(context.cwd, value);
    if (context.pathExists(localCandidate)) {
      return true;
    }
  }

  return true;
}

function firstLikelySourceAfterInstall(
  args: string[],
  installIndex: number,
  context?: SourceDetectionContext,
): string | null {
  for (let index = installIndex + 1; index < args.length; index += 1) {
    const token = args[index] ?? "";

    if (token === "--") {
      for (let tailIndex = index + 1; tailIndex < args.length; tailIndex += 1) {
        const candidate = args[tailIndex] ?? "";
        if (!candidate.startsWith("-")) {
          return candidate;
        }
      }
      return null;
    }

    if (token.startsWith("--")) {
      const [flag, inlineValue] = splitLongOption(token);
      if (inlineValue === null && isValueOption(flag)) {
        if (flag === "--version") {
          index += 1;
          continue;
        }
        index += 1;
      }
      continue;
    }

    if (token.startsWith("-")) {
      continue;
    }

    if (looksLikeSourceToken(token, context)) {
      // Heuristic to preserve forward compatibility with new ClawHub options:
      // if this token follows a flag and another source-like token follows,
      // treat this one as the option value and keep scanning.
      const previous = index > installIndex + 1 ? (args[index - 1] ?? "") : "";
      const next = args[index + 1] ?? "";
      if (previous.startsWith("-") && looksLikeSourceToken(next, context)) {
        continue;
      }
      return token;
    }
  }

  return null;
}

function requestedVersionAfterInstall(args: string[], installIndex: number): string | null {
  for (let index = installIndex + 1; index < args.length; index += 1) {
    const token = args[index] ?? "";
    if (token === "--") {
      return null;
    }

    if (!token.startsWith("--")) {
      continue;
    }

    const [flag, inlineValue] = splitLongOption(token);
    if (flag !== "--version") {
      continue;
    }

    if (inlineValue !== null) {
      const value = inlineValue.trim();
      return value.length > 0 ? value : null;
    }

    const next = args[index + 1] ?? "";
    if (next.trim().length === 0 || next.startsWith("-")) {
      return null;
    }

    return next.trim();
  }

  return null;
}

function findInstallSubcommandIndex(args: string[], context?: SourceDetectionContext): number {
  const [subcommand, subcommandIndex] = firstPositionalToken(args);
  if (subcommand === "install") {
    return subcommandIndex;
  }

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index]?.toLowerCase();
    if (token !== "install") {
      continue;
    }

    if (
      isLikelyLeadingGlobalOptionSequence(args, index) &&
      firstLikelySourceAfterInstall(args, index, context)
    ) {
      return index;
    }
  }

  return -1;
}

function normalizeSlashes(value: string): string {
  return value.replaceAll("\\", "/");
}

function sanitizeSlugForPath(slug: string): string {
  const segments = normalizeSlashes(slug)
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) => {
      const sanitized = segment.replace(/[^a-z0-9._-]/giu, "-");
      // Prevent "." and ".." from altering join() resolution semantics.
      return sanitized === "." || sanitized === ".." ? "_" : sanitized;
    })
    .filter((segment) => segment.length > 0);

  return segments.length > 0 ? segments.join("/") : "skill";
}

function sanitizeRelativeRemotePath(value: string): string {
  const normalized = normalizeSlashes(value).replace(/^\/+/, "");
  if (normalized.length === 0 || normalized.includes("\u0000")) {
    throw new Error(`Invalid file path returned by clawhub inspect: ${value}`);
  }

  const segments = normalized.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw new Error(`Unsafe file path returned by clawhub inspect: ${value}`);
  }

  return segments.join("/");
}

function parseJsonObjectFromCliOutput(raw: string, context: string): Record<string, unknown> {
  const trimmed = raw.trim();
  const start = trimmed.indexOf("{");
  if (start < 0) {
    throw new Error(`clawhub ${context} did not produce JSON output`);
  }

  const jsonCandidate = trimmed.slice(start);
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonCandidate) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse clawhub ${context} JSON output: ${message}`, {
      cause: error,
    });
  }

  if (!isRecord(parsed)) {
    throw new Error(`Unexpected clawhub ${context} JSON payload`);
  }

  return parsed;
}

function runClawhubCli(args: string[], cwd: string): string {
  // --yes avoids interactive install prompts when npx needs to fetch clawhub.
  const result = spawnSync("npx", [...NPX_CLAWHUB_BASE_ARGS, ...args], {
    cwd,
    encoding: "utf8",
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    const stderr = (result.stderr ?? "").trim();
    const stdout = (result.stdout ?? "").trim();
    throw new Error(
      stderr.length > 0
        ? stderr
        : stdout.length > 0
          ? stdout
          : `npx clawhub ${args.join(" ")} failed`,
    );
  }

  return result.stdout ?? "";
}

function extractInspectFiles(payload: Record<string, unknown>): string[] {
  const version = payload.version;
  if (!isRecord(version)) {
    return [];
  }

  const files = version.files;
  if (!Array.isArray(files)) {
    return [];
  }

  return files
    .filter((item): item is Record<string, unknown> => isRecord(item))
    .map((item) => item.path)
    .filter((path): path is string => typeof path === "string" && path.trim().length > 0);
}

function extractInspectFileContent(payload: Record<string, unknown>, fallbackPath: string): string {
  const file = payload.file;
  if (!isRecord(file)) {
    throw new Error(`clawhub inspect --file ${fallbackPath} did not return file metadata`);
  }

  const content = file.content;
  if (typeof content !== "string") {
    throw new Error(`clawhub inspect --file ${fallbackPath} did not return textual file content`);
  }

  return content;
}

function canonicalClawhubUrlFromSlug(slug: string): string {
  const normalized = normalizeSlashes(slug).replace(/^\/+/, "").replace(/\/+$/, "");
  return `https://clawhub.ai/${normalized}`;
}

function isLikelyLocalPathLike(value: string, context: SourceDetectionContext): boolean {
  if (
    value.startsWith("./") ||
    value.startsWith("../") ||
    value.startsWith("/") ||
    value.startsWith("~/") ||
    value.startsWith("~\\") ||
    value.includes("\\")
  ) {
    return true;
  }

  return context.pathExists(resolve(context.cwd, value));
}

function extractClawhubSlugFromSource(
  source: string,
  context: SourceDetectionContext,
): string | null {
  const trimmed = source.trim();
  if (trimmed.length === 0 || trimmed.startsWith("-")) {
    return null;
  }

  if (isLikelyHttpUrl(trimmed)) {
    try {
      const url = new URL(trimmed);
      if (!url.hostname.toLowerCase().endsWith("clawhub.ai")) {
        return null;
      }

      const normalizedPath = url.pathname.replace(/^\/+/, "").replace(/\/+$/, "");
      return normalizedPath.length > 0 ? decodeURIComponent(normalizedPath) : null;
    } catch {
      return null;
    }
  }

  if (isLikelyLocalPathLike(trimmed, context)) {
    return null;
  }

  return trimmed;
}

async function stageClawhubSkillFromInspect(input: {
  slug: string;
  version?: string;
  cwd: string;
  displayTarget: string;
}): Promise<ResolvedScanTarget> {
  const versionArgs = input.version ? ["--version", input.version] : [];
  const filesPayload = parseJsonObjectFromCliOutput(
    runClawhubCli(["inspect", "--json", "--files", ...versionArgs, input.slug], input.cwd),
    "inspect --files",
  );

  const filePaths = extractInspectFiles(filesPayload);
  if (filePaths.length === 0) {
    throw new Error(`clawhub inspect returned no files for ${input.slug}`);
  }
  const uniqueSortedFilePaths = [...new Set(filePaths)].sort((left, right) =>
    left.localeCompare(right),
  );

  const tempRoot = mkdtempSync(join(tmpdir(), "codegate-scan-clawhub-"));
  const stageRoot = join(tempRoot, "staged");
  const stageSkillRoot = join(stageRoot, "skills", sanitizeSlugForPath(input.slug));

  try {
    for (const path of uniqueSortedFilePaths) {
      const filePayload = parseJsonObjectFromCliOutput(
        runClawhubCli(["inspect", "--json", "--file", path, ...versionArgs, input.slug], input.cwd),
        `inspect --file ${path}`,
      );
      const content = extractInspectFileContent(filePayload, path);
      const safeRelativePath = sanitizeRelativeRemotePath(path);
      const destination = join(stageSkillRoot, safeRelativePath);
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, content, "utf8");
    }

    return {
      scanTarget: stageRoot,
      displayTarget: input.displayTarget,
      cleanup: () => rmSync(tempRoot, { recursive: true, force: true }),
    };
  } catch (error) {
    rmSync(tempRoot, { recursive: true, force: true });
    throw error;
  }
}

async function stageClawhubTargetDefault(
  input: {
    sourceTarget: string;
    requestedVersion?: string;
    cwd: string;
  },
  deps: {
    pathExists: (path: string) => boolean;
    resolveScanTarget: (input: {
      rawTarget: string;
      cwd: string;
      preferredSkill?: string;
      interactive?: boolean;
      requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
    }) => Promise<ResolvedScanTarget> | ResolvedScanTarget;
  },
): Promise<ResolvedScanTarget> {
  const sourceContext: SourceDetectionContext = {
    cwd: input.cwd,
    pathExists: deps.pathExists,
  };

  const slug = extractClawhubSlugFromSource(input.sourceTarget, sourceContext);
  if (slug) {
    return stageClawhubSkillFromInspect({
      slug,
      version: input.requestedVersion,
      cwd: input.cwd,
      displayTarget: isLikelyHttpUrl(input.sourceTarget)
        ? input.sourceTarget
        : canonicalClawhubUrlFromSlug(slug),
    });
  }

  return await deps.resolveScanTarget({
    rawTarget: input.sourceTarget,
    cwd: input.cwd,
  });
}

export interface ClawhubWrapperRuntimeOptions {
  force: boolean;
  noTui: boolean;
  includeUserScope: boolean;
  format?: OutputFormat;
  configPath?: string;
}

export interface ParsedClawhubInvocation {
  passthroughArgs: string[];
  wrapper: ClawhubWrapperRuntimeOptions;
  subcommand: string | null;
  sourceTarget: string | null;
  requestedVersion: string | null;
}

export interface ClawhubWrapperLaunchResult {
  status: number | null;
  error?: Error;
}

export interface ExecuteClawhubWrapperInput {
  version: string;
  clawhubArgs: string[];
}

export interface ClawhubWarningConsentContext {
  target: string;
  report: CodeGateReport;
}

export interface ClawhubWrapperDeps {
  cwd: () => string;
  isTTY: () => boolean;
  pathExists?: (path: string) => boolean;
  resolveConfig: (options: ResolveConfigOptions) => CodeGateConfig;
  runScan: (input: ScanRunnerInput) => Promise<CodeGateReport>;
  resolveScanTarget?: (input: {
    rawTarget: string;
    cwd: string;
    preferredSkill?: string;
    interactive?: boolean;
    requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
  }) => Promise<ResolvedScanTarget> | ResolvedScanTarget;
  stageClawhubTarget?: (input: {
    sourceTarget: string;
    requestedVersion?: string;
    cwd: string;
  }) => Promise<ResolvedScanTarget> | ResolvedScanTarget;
  requestWarningProceed?: (context: ClawhubWarningConsentContext) => Promise<boolean> | boolean;
  launchClawhub: (args: string[], cwd: string) => ClawhubWrapperLaunchResult;
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  setExitCode: (code: number) => void;
  renderTui?: (props: {
    view: "dashboard" | "summary";
    report: CodeGateReport;
    notices?: string[];
  }) => void;
}

export function parseClawhubInvocation(
  rawArgs: string[],
  context?: SourceDetectionContext,
): ParsedClawhubInvocation {
  const wrapper: ClawhubWrapperRuntimeOptions = {
    force: false,
    noTui: false,
    includeUserScope: false,
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
    if (token === "--cg-no-tui") {
      wrapper.noTui = true;
      continue;
    }
    if (token === "--cg-include-user-scope") {
      wrapper.includeUserScope = true;
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
    if (token.startsWith("--cg-")) {
      throw new Error(`Unknown CodeGate wrapper option: ${token}`);
    }

    passthroughArgs.push(token);
  }

  const installSubcommandIndex = findInstallSubcommandIndex(passthroughArgs, context);
  const subcommand =
    installSubcommandIndex >= 0 ? "install" : firstPositionalToken(passthroughArgs)[0];
  const sourceTarget =
    installSubcommandIndex >= 0
      ? firstLikelySourceAfterInstall(passthroughArgs, installSubcommandIndex, context)
      : null;
  const requestedVersion =
    installSubcommandIndex >= 0
      ? requestedVersionAfterInstall(passthroughArgs, installSubcommandIndex)
      : null;

  return {
    passthroughArgs,
    wrapper,
    subcommand,
    sourceTarget,
    requestedVersion,
  };
}

async function promptWarningProceed(context: ClawhubWarningConsentContext): Promise<boolean> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  const prompt = [
    `Warning findings detected for ${context.target}.`,
    `Findings: ${context.report.summary.total}`,
    "Proceed with clawhub install? [y/N]: ",
  ].join("\n");

  try {
    const answer = await rl.question(prompt);
    return /^y(es)?$/iu.test(answer.trim());
  } finally {
    rl.close();
  }
}

function finalizeLaunch(result: ClawhubWrapperLaunchResult, deps: ClawhubWrapperDeps): void {
  if (result.error) {
    deps.stderr(`Failed to run npx clawhub: ${result.error.message}`);
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

export function launchClawhubPassthrough(args: string[], cwd: string): ClawhubWrapperLaunchResult {
  const result = spawnSync("npx", [...NPX_CLAWHUB_BASE_ARGS, ...args], {
    cwd,
    stdio: "inherit",
  });
  return {
    status: result.status,
    error: result.error ?? undefined,
  };
}

export async function executeClawhubWrapper(
  input: ExecuteClawhubWrapperInput,
  deps: ClawhubWrapperDeps,
): Promise<void> {
  const cwd = deps.cwd();
  const isTTY = deps.isTTY();
  const pathExists = deps.pathExists ?? ((path: string) => existsSync(path));
  const sourceDetectionContext: SourceDetectionContext = { cwd, pathExists };
  const parsed = parseClawhubInvocation(input.clawhubArgs, sourceDetectionContext);

  if (parsed.subcommand !== "install") {
    finalizeLaunch(deps.launchClawhub(parsed.passthroughArgs, cwd), deps);
    return;
  }

  const resolvedSourceTarget = parsed.sourceTarget;
  if (!resolvedSourceTarget) {
    deps.stderr(
      "Could not determine the source target for `clawhub install`. Provide a skill slug or source target after `install`.",
    );
    deps.setExitCode(3);
    return;
  }

  let resolvedTarget: ResolvedScanTarget | undefined;
  const interactivePromptsEnabled = isTTY && parsed.wrapper.noTui !== true;

  try {
    const resolveTarget =
      deps.resolveScanTarget ??
      ((resolverInput: {
        rawTarget: string;
        cwd: string;
        preferredSkill?: string;
        interactive?: boolean;
        requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
      }) => resolveScanTarget(resolverInput));

    const stageClawhubTarget =
      deps.stageClawhubTarget ??
      ((stageInput: { sourceTarget: string; requestedVersion?: string; cwd: string }) =>
        stageClawhubTargetDefault(stageInput, {
          pathExists,
          resolveScanTarget: resolveTarget,
        }));

    resolvedTarget = await stageClawhubTarget({
      sourceTarget: resolvedSourceTarget,
      requestedVersion: parsed.requestedVersion ?? undefined,
      cwd,
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
    const config = parsed.wrapper.includeUserScope
      ? { ...baseConfig, scan_user_scope: true }
      : baseConfig;

    let report = await deps.runScan({
      version: input.version,
      scanTarget: resolvedTarget.scanTarget,
      config,
      flags: {
        noTui,
        format: parsed.wrapper.format,
        force: parsed.wrapper.force,
        includeUserScope: parsed.wrapper.includeUserScope,
      },
      discoveryContext: undefined,
    });

    if (resolvedTarget.displayTarget && resolvedTarget.displayTarget !== report.scan_target) {
      report = {
        ...report,
        scan_target: resolvedTarget.displayTarget,
      };
    }

    report = applyConfigPolicy(report, config);
    report = reorderRequestedTargetFindings(report, resolvedTarget.displayTarget);

    const shouldUseTui =
      config.tui.enabled && isTTY && deps.renderTui !== undefined && noTui !== true;
    const targetSummaryNote =
      config.output_format === "terminal"
        ? summarizeRequestedTargetFindings(report, resolvedTarget.displayTarget)
        : null;

    if (shouldUseTui) {
      deps.renderTui?.({
        view: "dashboard",
        report,
        notices: targetSummaryNote ? [targetSummaryNote] : undefined,
      });
      deps.renderTui?.({ view: "summary", report });
    } else {
      if (targetSummaryNote) {
        deps.stdout(targetSummaryNote);
      }
      deps.stdout(renderByFormat(config.output_format, report));
    }

    if (report.summary.exit_code === 2 && parsed.wrapper.force !== true) {
      deps.stderr("Dangerous findings detected. Aborting `clawhub install` (fail-closed).");
      deps.setExitCode(2);
      return;
    }

    if (shouldPromptForWarning(report, config, parsed.wrapper.force)) {
      if (!interactivePromptsEnabled) {
        deps.stderr(
          "Warning findings detected. Aborting `clawhub install` in non-interactive mode (fail-closed). Use --cg-force to override.",
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

  finalizeLaunch(deps.launchClawhub(parsed.passthroughArgs, cwd), deps);
}
