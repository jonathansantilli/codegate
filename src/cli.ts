#!/usr/bin/env node

import { existsSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { pathToFileURL } from "node:url";
import { Command, Option } from "commander";
import {
  DEFAULT_CONFIG,
  OUTPUT_FORMATS,
  resolveEffectiveConfig,
  type CliConfigOverrides,
  type CodeGateConfig,
  type OutputFormat,
  type ResolveConfigOptions,
} from "./config.js";
import { APP_NAME } from "./index.js";
import type { ResourceFetchResult } from "./layer3-dynamic/resource-fetcher.js";
import type { LocalTextAnalysisTarget } from "./layer3-dynamic/local-text-analysis.js";
import { runSandboxCommand } from "./layer3-dynamic/sandbox.js";
import { loadKnowledgeBase } from "./layer1-discovery/knowledge-base.js";
import { type DeepScanResource } from "./pipeline.js";
import {
  createScanDiscoveryContext,
  discoverDeepScanResources,
  discoverDeepScanResourcesFromContext,
  discoverLocalTextAnalysisTargetsFromContext,
  runScanEngine,
  type ScanDiscoveryCandidate,
  type ScanDiscoveryContext,
} from "./scan.js";
import { registerSignalHandlers } from "./runtime/signal-handlers.js";
import { resolveScanTarget, type ResolvedScanTarget } from "./scan-target.js";
import { renderTuiApp } from "./tui/app.js";
import { executeWrapperRun } from "./wrapper.js";
import type { CodeGateReport } from "./types/report.js";
import {
  runRemediation as runRemediationWorkflow,
  type RemediationRunnerInput,
  type RemediationRunnerResult,
} from "./layer4-remediation/remediation-runner.js";
import { undoLatestSession } from "./commands/undo.js";
import { executeScanCommand } from "./commands/scan-command.js";
import {
  executeSkillsWrapper,
  launchSkillsPassthrough,
  type SkillsWrapperLaunchResult,
} from "./commands/skills-wrapper.js";
import {
  executeClawhubWrapper,
  launchClawhubPassthrough,
  type ClawhubWrapperLaunchResult,
} from "./commands/clawhub-wrapper.js";
import {
  type DeepAgentOption,
  type MetaAgentCommandConsentContext,
  type MetaAgentCommandRunResult,
  type RemediationConsentContext,
  type ScanCommandOptions,
  type ScanRunnerInput,
} from "./commands/scan-command.js";
import {
  promptDeepAgentSelection,
  promptDeepScanConsent,
  promptMetaAgentCommandConsent,
  promptRemediationConsent,
  promptSkillSelection,
} from "./cli-prompts.js";
import { resetScanState } from "./layer2-static/state/scan-state.js";

const require = createRequire(import.meta.url);
const packageJson = require("../package.json") as { version?: string };

export interface RunWarningConsentContext {
  target: string;
  report: CodeGateReport;
}

export interface CliDeps {
  cwd: () => string;
  isTTY: () => boolean;
  homeDir?: () => string;
  pathExists?: (path: string) => boolean;
  resolveConfig: (options: ResolveConfigOptions) => CodeGateConfig;
  runScan: (input: ScanRunnerInput) => Promise<CodeGateReport>;
  prepareScanDiscovery?: (
    scanTarget: string,
    config?: CodeGateConfig,
    options?: { explicitCandidates?: ScanDiscoveryCandidate[] },
  ) => Promise<ScanDiscoveryContext> | ScanDiscoveryContext;
  resolveScanTarget?: (input: {
    rawTarget: string;
    cwd: string;
    preferredSkill?: string;
    interactive?: boolean;
    requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
  }) => Promise<ResolvedScanTarget> | ResolvedScanTarget;
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  writeFile: (path: string, content: string) => void;
  setExitCode: (code: number) => void;
  renderTui?: (props: {
    view: "dashboard" | "summary";
    report: CodeGateReport;
    notices?: string[];
  }) => void;
  runRemediation?: (
    input: RemediationRunnerInput,
  ) => Promise<RemediationRunnerResult> | RemediationRunnerResult;
  runUndo?: (projectRoot: string) => { restoredFiles: number; sessionId: string };
  resetScanState?: (path?: string) => Promise<void> | void;
  discoverDeepResources?: (
    scanTarget: string,
    config?: CodeGateConfig,
    discoveryContext?: ScanDiscoveryContext,
  ) => Promise<DeepScanResource[]> | DeepScanResource[];
  discoverLocalTextTargets?: (
    scanTarget: string,
    config?: CodeGateConfig,
    discoveryContext?: ScanDiscoveryContext,
  ) => Promise<LocalTextAnalysisTarget[]> | LocalTextAnalysisTarget[];
  requestDeepScanConsent?: (resource: DeepScanResource) => Promise<boolean> | boolean;
  requestDeepAgentSelection?: (
    options: DeepAgentOption[],
  ) => Promise<DeepAgentOption | null> | DeepAgentOption | null;
  requestMetaAgentCommandConsent?: (
    context: MetaAgentCommandConsentContext,
  ) => Promise<boolean> | boolean;
  runMetaAgentCommand?: (
    context: MetaAgentCommandConsentContext,
  ) => Promise<MetaAgentCommandRunResult> | MetaAgentCommandRunResult;
  requestRemediationConsent?: (context: RemediationConsentContext) => Promise<boolean> | boolean;
  requestRunWarningConsent?: (context: RunWarningConsentContext) => Promise<boolean> | boolean;
  requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
  executeDeepResource?: (resource: DeepScanResource) => Promise<ResourceFetchResult>;
  launchSkills?: (args: string[], cwd: string) => SkillsWrapperLaunchResult;
  launchClawhub?: (args: string[], cwd: string) => ClawhubWrapperLaunchResult;
  runSkillsWrapper?: (input: { version: string; skillsArgs: string[] }) => Promise<void>;
  runClawhubWrapper?: (input: { version: string; clawhubArgs: string[] }) => Promise<void>;
  runWrapper?: (input: {
    target: string;
    cwd: string;
    version: string;
    config: CodeGateConfig;
    force?: boolean;
    requestWarningProceed?: (report: CodeGateReport) => Promise<boolean> | boolean;
  }) => Promise<void>;
}

function isNoTuiEnabled(options: { noTui?: boolean; tui?: boolean }): boolean {
  return options.noTui === true || options.tui === false;
}

function renderExampleHelp(lines: string[]): string {
  return ["", "Examples:", ...lines.map((line) => `  ${line}`)].join("\n");
}

export function isDirectCliInvocation(
  importMetaUrl: string,
  argv1: string | undefined,
  deps: { realpath?: (path: string) => string } = {},
): boolean {
  if (!argv1) {
    return false;
  }

  const argvUrl = pathToFileURL(argv1).href;
  if (argvUrl === importMetaUrl) {
    return true;
  }

  const resolveRealpath = deps.realpath ?? ((path: string) => realpathSync(path));
  try {
    const resolvedArgvUrl = pathToFileURL(resolveRealpath(argv1)).href;
    return resolvedArgvUrl === importMetaUrl;
  } catch {
    return false;
  }
}

async function runMetaAgentCommandWithSandbox(
  context: MetaAgentCommandConsentContext,
): Promise<MetaAgentCommandRunResult> {
  const commandResult = await runSandboxCommand({
    command: context.command.command,
    args: context.command.args,
    cwd: context.command.cwd,
    timeoutMs: context.command.timeoutMs,
  });
  return {
    command: context.command,
    code: commandResult.code,
    stdout: commandResult.stdout,
    stderr: commandResult.stderr,
  };
}

function resolveInteractiveCallback<T>(input: {
  enabled: boolean;
  provided?: T;
  fallback?: T;
}): T | undefined {
  if (!input.enabled) {
    return undefined;
  }
  return input.provided ?? input.fallback;
}

function buildWrapperScanBridgeDeps(deps: CliDeps): {
  prepareScanDiscovery: CliDeps["prepareScanDiscovery"];
  discoverDeepResources: CliDeps["discoverDeepResources"];
  discoverLocalTextTargets: CliDeps["discoverLocalTextTargets"];
  requestDeepScanConsent: CliDeps["requestDeepScanConsent"];
  requestDeepAgentSelection: CliDeps["requestDeepAgentSelection"];
  requestMetaAgentCommandConsent: CliDeps["requestMetaAgentCommandConsent"];
  runMetaAgentCommand: NonNullable<CliDeps["runMetaAgentCommand"]>;
  executeDeepResource: CliDeps["executeDeepResource"];
} {
  const isTTY = deps.isTTY();
  return {
    prepareScanDiscovery: deps.prepareScanDiscovery,
    discoverDeepResources: deps.discoverDeepResources,
    discoverLocalTextTargets: deps.discoverLocalTextTargets,
    requestDeepScanConsent: resolveInteractiveCallback({
      enabled: true,
      provided: deps.requestDeepScanConsent,
      fallback: isTTY ? promptDeepScanConsent : undefined,
    }),
    requestDeepAgentSelection: resolveInteractiveCallback({
      enabled: true,
      provided: deps.requestDeepAgentSelection,
      fallback: isTTY ? promptDeepAgentSelection : undefined,
    }),
    requestMetaAgentCommandConsent: resolveInteractiveCallback({
      enabled: true,
      provided: deps.requestMetaAgentCommandConsent,
      fallback: isTTY ? promptMetaAgentCommandConsent : undefined,
    }),
    runMetaAgentCommand: deps.runMetaAgentCommand ?? runMetaAgentCommandWithSandbox,
    executeDeepResource: deps.executeDeepResource,
  };
}

async function promptRunWarningConsent(context: RunWarningConsentContext): Promise<boolean> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = [
    `Warning findings detected for ${context.target}.`,
    `Findings: ${context.report.summary.total}`,
    "These findings are below the blocking threshold but still require confirmation to launch.",
    "Proceed with launch? [y/N]: ",
  ].join("\n");

  try {
    const answer = await rl.question(prompt);
    return /^y(es)?$/iu.test(answer.trim());
  } finally {
    rl.close();
  }
}

const defaultCliDeps: CliDeps = {
  cwd: () => process.cwd(),
  isTTY: () => process.stdout.isTTY === true,
  homeDir: () => homedir(),
  pathExists: (path) => existsSync(path),
  resolveConfig: (options) => resolveEffectiveConfig(options),
  runScan: async (input) =>
    runScanEngine({
      version: input.version,
      scanTarget: input.scanTarget,
      config: input.config,
      scanStatePath: input.config.scan_state_path,
      discoveryContext: input.discoveryContext,
    }),
  prepareScanDiscovery: (scanTarget, config, options) =>
    createScanDiscoveryContext(scanTarget, undefined, {
      includeUserScope: config?.scan_user_scope === true,
      parseSelected: true,
      explicitCandidates: options?.explicitCandidates,
    }),
  resolveScanTarget: (input) => resolveScanTarget(input),
  stdout: (message) => {
    process.stdout.write(`${message}\n`);
  },
  stderr: (message) => {
    process.stderr.write(`${message}\n`);
  },
  writeFile: (path, content) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content, "utf8");
  },
  setExitCode: (code) => {
    process.exitCode = code;
  },
  renderTui: (props) => {
    renderTuiApp({
      view: props.view,
      report: props.report,
      notices: props.notices,
    });
  },
  runRemediation: (input) => runRemediationWorkflow(input),
  runUndo: (projectRoot) => undoLatestSession({ projectRoot }),
  resetScanState: (path) => resetScanState(path),
  discoverDeepResources: (scanTarget, config, discoveryContext) =>
    discoveryContext
      ? discoverDeepScanResourcesFromContext(discoveryContext)
      : discoverDeepScanResources(scanTarget, undefined, {
          includeUserScope: config?.scan_user_scope === true,
        }),
  discoverLocalTextTargets: (_scanTarget, _config, discoveryContext) =>
    discoveryContext ? discoverLocalTextAnalysisTargetsFromContext(discoveryContext) : [],
  // Deep resource execution never makes outbound network calls.
  // Connecting to URLs found in scanned config files is a security risk:
  // the endpoint could be malicious (crafted responses, SSRF, IP logging).
  // Instead, we record the URL as metadata for the agent to analyze.
  executeDeepResource: async (resource) => {
    return {
      status: "ok" as const,
      attempts: 0,
      elapsedMs: 0,
      metadata: {
        resource_id: resource.id,
        resource_kind: resource.request.kind,
        resource_url: resource.request.locator,
        note: "URL recorded for analysis without making outbound connections.",
      },
    };
  },
  launchSkills: (args, cwd) => launchSkillsPassthrough(args, cwd),
  launchClawhub: (args, cwd) => launchClawhubPassthrough(args, cwd),
};

function addScanCommand(program: Command, version: string, deps: CliDeps): void {
  program
    .command("scan [target]")
    .description("Scan a local path or URL target for AI tool config risks")
    .option("--deep", "enable Layer 3 dynamic analysis")
    .option("--remediate", "enter remediation mode after scan")
    .option("--fix-safe", "auto-fix unambiguous critical findings")
    .option("--dry-run", "show proposed fixes but write nothing")
    .option("--patch", "generate a patch file for review")
    .option("--no-tui", "disable TUI and interactive prompts")
    .addOption(
      new Option("--format <type>", "output format")
        .choices([...OUTPUT_FORMATS])
        .argParser((value) => value as OutputFormat),
    )
    .option("--output <path>", "write report to file")
    .option("--verbose", "show extended output")
    .option("--config <path>", "use a specific global config file")
    .option("--force", "skip interactive confirmations")
    .option("--include-user-scope", "include user/home AI tool config paths in scan")
    .option("--skill <name>", "select one skill directory when scanning a skills index repo URL")
    .option("--reset-state", "clear persisted scan-state history and exit")
    .addHelpText(
      "after",
      renderExampleHelp([
        "codegate scan .",
        "codegate scan ./skills/security-review/SKILL.md",
        "codegate scan https://github.com/owner/repo",
        "codegate scan https://github.com/owner/repo --skill security-review",
        "codegate scan https://github.com/owner/repo/blob/main/skills/security-review/SKILL.md",
        "codegate scan https://example.com/security-review/SKILL.md --format json",
      ]),
    )
    .action(async (target: string | undefined, options: ScanCommandOptions & { tui?: boolean }) => {
      const rawTarget = target ?? ".";
      const noTui = isNoTuiEnabled(options);
      const promptCallbacksEnabled = noTui !== true;
      const interactivePromptsEnabled = deps.isTTY() && noTui !== true;
      const cliConfig: CliConfigOverrides = {
        format: options.format,
        configPath: options.config,
        noTui: noTui || !deps.isTTY(),
      };
      let resolvedTarget: ResolvedScanTarget | undefined;

      try {
        const resolveTarget =
          deps.resolveScanTarget ??
          ((input: {
            rawTarget: string;
            cwd: string;
            preferredSkill?: string;
            interactive?: boolean;
            requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
          }) => resolveScanTarget(input));
        resolvedTarget = await resolveTarget({
          rawTarget,
          cwd: deps.cwd(),
          preferredSkill: options.skill,
          interactive: interactivePromptsEnabled,
          requestSkillSelection: promptCallbacksEnabled
            ? (deps.requestSkillSelection ??
              (interactivePromptsEnabled ? promptSkillSelection : undefined))
            : undefined,
        });
        const scanTarget = resolvedTarget.scanTarget;
        const baseConfig = deps.resolveConfig({
          scanTarget,
          cli: cliConfig,
        });
        const config =
          options.includeUserScope === true
            ? {
                ...baseConfig,
                scan_user_scope: true,
              }
            : baseConfig;

        if (options.resetState) {
          const reset = deps.resetScanState ?? ((path?: string) => resetScanState(path));
          await reset(config.scan_state_path);
          deps.stdout("Scan state reset.");
          deps.setExitCode(0);
          return;
        }

        await executeScanCommand(
          {
            version,
            cwd: resolve(deps.cwd()),
            scanTarget,
            displayTarget: resolvedTarget.displayTarget,
            explicitCandidates: resolvedTarget.explicitCandidates,
            config,
            options: {
              ...options,
              noTui,
            },
          },
          {
            isTTY: deps.isTTY,
            runScan: deps.runScan,
            prepareScanDiscovery: deps.prepareScanDiscovery,
            discoverDeepResources: deps.discoverDeepResources,
            discoverLocalTextTargets: deps.discoverLocalTextTargets,
            requestDeepScanConsent: resolveInteractiveCallback({
              enabled: promptCallbacksEnabled,
              provided: deps.requestDeepScanConsent,
              fallback: interactivePromptsEnabled ? promptDeepScanConsent : undefined,
            }),
            requestDeepAgentSelection: resolveInteractiveCallback({
              enabled: promptCallbacksEnabled,
              provided: deps.requestDeepAgentSelection,
              fallback: interactivePromptsEnabled ? promptDeepAgentSelection : undefined,
            }),
            requestMetaAgentCommandConsent: resolveInteractiveCallback({
              enabled: promptCallbacksEnabled,
              provided: deps.requestMetaAgentCommandConsent,
              fallback: interactivePromptsEnabled ? promptMetaAgentCommandConsent : undefined,
            }),
            executeDeepResource: deps.executeDeepResource,
            runMetaAgentCommand: deps.runMetaAgentCommand ?? runMetaAgentCommandWithSandbox,
            requestRemediationConsent: resolveInteractiveCallback({
              enabled: promptCallbacksEnabled,
              provided: deps.requestRemediationConsent,
              fallback: interactivePromptsEnabled ? promptRemediationConsent : undefined,
            }),
            runRemediation: deps.runRemediation,
            stdout: deps.stdout,
            stderr: deps.stderr,
            writeFile: deps.writeFile,
            setExitCode: deps.setExitCode,
            renderTui: deps.renderTui,
          },
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        deps.stderr(`Scan failed: ${message}`);
        deps.setExitCode(3);
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
    });
}

function addRunCommand(program: Command, version: string, deps: CliDeps): void {
  program
    .command("run <tool>")
    .description("Scan current directory, then launch an AI coding tool")
    .option("--no-tui", "disable TUI and interactive prompts")
    .option("--config <path>", "use a specific global config file")
    .option("--force", "skip interactive confirmations")
    .addHelpText(
      "after",
      renderExampleHelp([
        "codegate run claude",
        "codegate run codex --force",
        "codegate run cursor",
      ]),
    )
    .action(
      async (
        tool: string,
        options: { noTui?: boolean; tui?: boolean; config?: string; force?: boolean },
      ) => {
        const cwd = resolve(deps.cwd());
        const noTui = isNoTuiEnabled(options);
        const cliConfig: CliConfigOverrides = {
          configPath: options.config,
          noTui: noTui || !deps.isTTY(),
        };

        try {
          const config = deps.resolveConfig({
            scanTarget: cwd,
            cli: cliConfig,
          });
          const runWrapper =
            deps.runWrapper ??
            ((input: {
              target: string;
              cwd: string;
              version: string;
              config: CodeGateConfig;
              force?: boolean;
              requestWarningProceed?: (report: CodeGateReport) => Promise<boolean> | boolean;
            }) => {
              const shouldUseTui =
                config.tui.enabled && deps.isTTY() && deps.renderTui !== undefined;
              return executeWrapperRun({
                target: input.target,
                cwd: input.cwd,
                version: input.version,
                config: input.config,
                force: input.force,
                onReport: shouldUseTui
                  ? (report) => {
                      deps.renderTui?.({ view: "dashboard", report });
                      deps.renderTui?.({ view: "summary", report });
                    }
                  : undefined,
                requestWarningProceed: input.requestWarningProceed,
              });
            });

          await runWrapper({
            target: tool,
            cwd,
            version,
            config,
            force: options.force,
            requestWarningProceed:
              options.force || !deps.isTTY() || noTui === true
                ? undefined
                : async (report) => {
                    const requestConsent =
                      deps.requestRunWarningConsent ??
                      ((context: RunWarningConsentContext) => promptRunWarningConsent(context));
                    return await requestConsent({ target: tool, report });
                  },
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          deps.stderr(`Run failed: ${message}`);
          deps.setExitCode(3);
        }
      },
    );
}

function addSkillsCommand(program: Command, version: string, deps: CliDeps): void {
  program
    .command("skills [skillsArgs...]")
    .description("Wrap npx skills with CodeGate preflight scanning for installs")
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .addHelpText(
      "after",
      renderExampleHelp([
        "codegate skills add vercel-labs/skills --skill find-skills",
        "codegate skills add https://github.com/owner/repo --skill security-review",
        "codegate skills add owner/repo --skill demo --cg-deep",
        "codegate skills find security",
        "codegate skills add owner/repo --skill demo --cg-force",
      ]),
    )
    .action(async (skillsArgs: string[] | undefined) => {
      try {
        const runSkillsWrapper =
          deps.runSkillsWrapper ??
          ((input: { version: string; skillsArgs: string[] }) =>
            executeSkillsWrapper(input, {
              cwd: deps.cwd,
              isTTY: deps.isTTY,
              pathExists: deps.pathExists,
              resolveConfig: deps.resolveConfig,
              runScan: deps.runScan,
              ...buildWrapperScanBridgeDeps(deps),
              resolveScanTarget: deps.resolveScanTarget,
              requestSkillSelection: deps.requestSkillSelection,
              requestWarningProceed: deps.requestRunWarningConsent,
              launchSkills:
                deps.launchSkills ?? ((args, cwd) => launchSkillsPassthrough(args, cwd)),
              stdout: deps.stdout,
              stderr: deps.stderr,
              setExitCode: deps.setExitCode,
              renderTui: deps.renderTui,
            }));

        await runSkillsWrapper({
          version,
          skillsArgs: skillsArgs ?? [],
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        deps.stderr(`Skills wrapper failed: ${message}`);
        deps.setExitCode(3);
      }
    });
}

function addClawhubCommand(program: Command, version: string, deps: CliDeps): void {
  program
    .command("clawhub [clawhubArgs...]")
    .description("Wrap npx clawhub with CodeGate preflight scanning for installs")
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .addHelpText(
      "after",
      renderExampleHelp([
        "codegate clawhub install security-auditor",
        "codegate clawhub install security-auditor --version 1.0.0",
        "codegate clawhub install security-auditor --cg-deep",
        "codegate clawhub search security",
        "codegate clawhub install security-auditor --cg-force",
      ]),
    )
    .action(async (clawhubArgs: string[] | undefined) => {
      try {
        const runClawhubWrapper =
          deps.runClawhubWrapper ??
          ((input: { version: string; clawhubArgs: string[] }) =>
            executeClawhubWrapper(input, {
              cwd: deps.cwd,
              isTTY: deps.isTTY,
              pathExists: deps.pathExists,
              resolveConfig: deps.resolveConfig,
              runScan: deps.runScan,
              ...buildWrapperScanBridgeDeps(deps),
              resolveScanTarget: deps.resolveScanTarget,
              requestWarningProceed: deps.requestRunWarningConsent,
              launchClawhub:
                deps.launchClawhub ?? ((args, cwd) => launchClawhubPassthrough(args, cwd)),
              stdout: deps.stdout,
              stderr: deps.stderr,
              setExitCode: deps.setExitCode,
              renderTui: deps.renderTui,
            }));

        await runClawhubWrapper({
          version,
          clawhubArgs: clawhubArgs ?? [],
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        deps.stderr(`ClawHub wrapper failed: ${message}`);
        deps.setExitCode(3);
      }
    });
}

function addUndoCommand(program: Command, deps: CliDeps): void {
  program
    .command("undo [dir]")
    .description("Restore the most recent remediation backup session")
    .addHelpText("after", renderExampleHelp(["codegate undo", "codegate undo ./project"]))
    .action((dir: string | undefined) => {
      const projectRoot = resolve(deps.cwd(), dir ?? ".");
      try {
        const runUndo =
          deps.runUndo ?? ((target: string) => undoLatestSession({ projectRoot: target }));
        const result = runUndo(projectRoot);
        deps.stdout(
          `Restored ${result.restoredFiles} file(s) from backup session ${result.sessionId}.`,
        );
        deps.setExitCode(0);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        deps.stderr(`Undo failed: ${message}`);
        deps.setExitCode(3);
      }
    });
}

function addInitCommand(program: Command, deps: CliDeps): void {
  program
    .command("init")
    .description("Create ~/.codegate/config.json with defaults")
    .option("--path <path>", "write to a custom config path")
    .option("--force", "overwrite existing config file")
    .addHelpText(
      "after",
      renderExampleHelp([
        "codegate init",
        "codegate init --path ./.codegate/config.json",
        "codegate init --force",
      ]),
    )
    .action((options: { path?: string; force?: boolean }) => {
      try {
        const home = deps.homeDir?.() ?? homedir();
        const targetPath = options.path
          ? resolve(deps.cwd(), options.path)
          : resolve(home, ".codegate", "config.json");
        const pathExists = deps.pathExists ?? ((path: string) => existsSync(path));

        if (pathExists(targetPath) && !options.force) {
          deps.stderr(`Config already exists: ${targetPath}. Use --force to overwrite.`);
          deps.setExitCode(3);
          return;
        }

        deps.writeFile(targetPath, `${JSON.stringify(DEFAULT_CONFIG, null, 2)}\n`);
        deps.stdout(`Created config: ${targetPath}`);
        deps.setExitCode(0);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        deps.stderr(`Init failed: ${message}`);
        deps.setExitCode(3);
      }
    });
}

function addUpdateCommands(program: Command, deps: CliDeps): void {
  const guidance = [
    "Updates are bundled with CodeGate releases in v1/v2.",
    "Run: npm update -g codegate-ai",
    "Or run latest directly: npx codegate-ai@latest scan .",
  ];

  program
    .command("update-kb")
    .description("Check for newer knowledge-base content")
    .addHelpText("after", renderExampleHelp(["codegate update-kb"]))
    .action(() => {
      deps.stdout("update-kb:");
      for (const line of guidance) {
        deps.stdout(line);
      }
      deps.setExitCode(0);
    });

  program
    .command("update-rules")
    .description("Check for newer rules content")
    .addHelpText("after", renderExampleHelp(["codegate update-rules"]))
    .action(() => {
      deps.stdout("update-rules:");
      for (const line of guidance) {
        deps.stdout(line);
      }
      deps.setExitCode(0);
    });
}

function resolveKnowledgeBaseVersion(): string {
  try {
    return loadKnowledgeBase().schemaVersion;
  } catch {
    return "unknown";
  }
}

export function createCli(
  version = packageJson.version ?? "0.0.0-dev",
  deps: CliDeps = defaultCliDeps,
): Command {
  const program = new Command();
  const versionDisplay = `${version} (kb ${resolveKnowledgeBaseVersion()})`;
  program
    .name(APP_NAME)
    .description("Pre-flight security scanner for AI coding tool configurations.")
    .version(versionDisplay)
    .helpOption("-h, --help", "display help for command")
    .addHelpText(
      "after",
      renderExampleHelp([
        "codegate scan .",
        "codegate scan https://github.com/owner/repo",
        "codegate scan https://github.com/owner/repo/blob/main/skills/security-review/SKILL.md",
        "codegate skills add owner/repo --skill security-review",
        "codegate clawhub install security-auditor",
        "codegate run claude",
      ]),
    );

  addScanCommand(program, version, deps);
  addSkillsCommand(program, version, deps);
  addClawhubCommand(program, version, deps);
  addRunCommand(program, version, deps);
  addUndoCommand(program, deps);
  addInitCommand(program, deps);
  addUpdateCommands(program, deps);
  return program;
}

export async function runCli(
  argv = process.argv,
  version = packageJson.version ?? "0.0.0-dev",
  deps: CliDeps = defaultCliDeps,
): Promise<void> {
  const cli = createCli(version, deps);
  const cleanupSignals = registerSignalHandlers({
    onSignal: (signal) => {
      process.exitCode = signal === "SIGINT" ? 130 : 143;
    },
  });
  try {
    await cli.parseAsync(argv);
  } finally {
    cleanupSignals();
  }
}

if (isDirectCliInvocation(import.meta.url, process.argv[1])) {
  await runCli();
}
