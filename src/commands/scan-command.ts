import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { applyConfigPolicy, type CodeGateConfig, type OutputFormat } from "../config.js";
import {
  buildMetaAgentCommand,
  type MetaAgentCommand,
  type MetaAgentTool,
} from "../layer3-dynamic/command-builder.js";
import type { LocalTextAnalysisTarget } from "../layer3-dynamic/local-text-analysis.js";
import {
  buildPromptEvidenceText,
  supportsToollessLocalTextAnalysis,
} from "../layer3-dynamic/local-text-analysis.js";
import {
  buildLocalTextAnalysisPrompt,
  buildSecurityAnalysisPrompt,
} from "../layer3-dynamic/meta-agent.js";
import type { ResourceFetchResult } from "../layer3-dynamic/resource-fetcher.js";
import {
  layer3OutcomesToFindings,
  mergeLayer3Findings,
  runDeepScanWithConsent,
  type DeepScanResource,
} from "../pipeline.js";
import type { ScanDiscoveryCandidate, ScanDiscoveryContext } from "../scan.js";
import type { CodeGateReport } from "../types/report.js";
import type {
  RemediationRunnerInput,
  RemediationRunnerResult,
} from "../layer4-remediation/remediation-runner.js";
import {
  mergeMetaAgentMetadata,
  metadataSummary,
  noEligibleDeepResourceNotes,
  parseLocalTextFindings,
  parseMetaAgentOutput,
  remediationSummaryLines,
  renderByFormat,
  summarizeRequestedTargetFindings,
  withMetaAgentFinding,
} from "./scan-command/helpers.js";
import { reorderRequestedTargetFindings } from "../report/requested-target-findings.js";

export interface ScanCommandOptions {
  deep?: boolean;
  remediate?: boolean;
  fixSafe?: boolean;
  dryRun?: boolean;
  patch?: boolean;
  noTui?: boolean;
  format?: OutputFormat;
  output?: string;
  verbose?: boolean;
  config?: string;
  force?: boolean;
  resetState?: boolean;
  includeUserScope?: boolean;
  skill?: string;
}

export interface ScanRunnerInput {
  version: string;
  scanTarget: string;
  config: CodeGateConfig;
  flags: ScanCommandOptions;
  discoveryContext?: ScanDiscoveryContext;
}

export interface DeepAgentOption {
  id: "claude" | "codex" | "opencode";
  label: string;
  metaTool: MetaAgentTool;
  binary: string;
  detectedTool: string;
}

export interface MetaAgentCommandConsentContext {
  resource?: DeepScanResource;
  localFile?: LocalTextAnalysisTarget;
  agent: DeepAgentOption;
  command: MetaAgentCommand;
}

export interface MetaAgentCommandRunResult {
  command: MetaAgentCommand;
  code: number;
  stdout: string;
  stderr: string;
}

export interface RemediationConsentContext {
  scanTarget: string;
  totalFindings: number;
  fixableFindings: number;
  criticalFindings: number;
}

export interface ExecuteScanCommandInput {
  version: string;
  cwd: string;
  scanTarget: string;
  displayTarget?: string;
  explicitCandidates?: ScanDiscoveryCandidate[];
  config: CodeGateConfig;
  options: ScanCommandOptions;
}

export interface ExecuteScanCommandDeps {
  isTTY: () => boolean;
  runScan: (input: ScanRunnerInput) => Promise<CodeGateReport>;
  prepareScanDiscovery?: (
    scanTarget: string,
    config?: CodeGateConfig,
    options?: { explicitCandidates?: ScanDiscoveryCandidate[] },
  ) => Promise<ScanDiscoveryContext> | ScanDiscoveryContext;
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
  executeDeepResource?: (resource: DeepScanResource) => Promise<ResourceFetchResult>;
  runRemediation?: (
    input: RemediationRunnerInput,
  ) => Promise<RemediationRunnerResult> | RemediationRunnerResult;
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  writeFile: (path: string, content: string) => void;
  setExitCode: (code: number) => void;
  renderTui?: (props: {
    view: "dashboard" | "summary";
    report: CodeGateReport;
    notices?: string[];
  }) => void;
}

type ScanAnalysisDepKeys =
  | "isTTY"
  | "runScan"
  | "prepareScanDiscovery"
  | "discoverDeepResources"
  | "discoverLocalTextTargets"
  | "requestDeepScanConsent"
  | "requestDeepAgentSelection"
  | "requestMetaAgentCommandConsent"
  | "runMetaAgentCommand"
  | "executeDeepResource";

export type ScanAnalysisDeps = Pick<ExecuteScanCommandDeps, ScanAnalysisDepKeys>;

export type ScanAnalysisInput = Omit<ExecuteScanCommandInput, "cwd">;

export interface ScanAnalysisResult {
  report: CodeGateReport;
  deepScanNotes: string[];
}

function toMetaAgentPreference(value: string): DeepAgentOption["id"] | null {
  const normalized = value.trim().toLowerCase();
  if (normalized === "claude" || normalized === "claude-code") {
    return "claude";
  }
  if (normalized === "codex" || normalized === "codex-cli") {
    return "codex";
  }
  if (normalized === "opencode") {
    return "opencode";
  }
  return null;
}

function deepAgentOptions(report: CodeGateReport, config: CodeGateConfig): DeepAgentOption[] {
  const detected = new Set(report.tools_detected);
  const skipTools = new Set(
    config.tool_discovery.skip_tools.map((tool) => tool.trim().toLowerCase()),
  );
  const preferred = toMetaAgentPreference(config.tool_discovery.preferred_agent);
  const candidates: DeepAgentOption[] = [];

  if (detected.has("claude-code") && !skipTools.has("claude") && !skipTools.has("claude-code")) {
    candidates.push({
      id: "claude",
      label: "Claude Code",
      metaTool: "claude",
      binary:
        config.tool_discovery.agent_paths.claude ??
        config.tool_discovery.agent_paths["claude-code"] ??
        "claude",
      detectedTool: "claude-code",
    });
  }

  if (detected.has("codex-cli") && !skipTools.has("codex") && !skipTools.has("codex-cli")) {
    candidates.push({
      id: "codex",
      label: "Codex CLI",
      metaTool: "codex",
      binary:
        config.tool_discovery.agent_paths.codex ??
        config.tool_discovery.agent_paths["codex-cli"] ??
        "codex",
      detectedTool: "codex-cli",
    });
  }

  if (detected.has("opencode") && !skipTools.has("opencode")) {
    candidates.push({
      id: "opencode",
      label: "OpenCode",
      metaTool: "generic",
      binary: config.tool_discovery.agent_paths.opencode ?? "opencode",
      detectedTool: "opencode",
    });
  }

  const order: DeepAgentOption["id"][] = ["claude", "codex", "opencode"];
  return candidates.sort((left, right) => {
    if (preferred && left.id === preferred && right.id !== preferred) {
      return -1;
    }
    if (preferred && right.id === preferred && left.id !== preferred) {
      return 1;
    }
    return order.indexOf(left.id) - order.indexOf(right.id);
  });
}

export async function runScanAnalysis(
  input: ScanAnalysisInput,
  deps: ScanAnalysisDeps,
): Promise<ScanAnalysisResult> {
  const interactivePromptsEnabled = deps.isTTY() && input.options.noTui !== true;
  const discoveryContext = deps.prepareScanDiscovery
    ? await deps.prepareScanDiscovery(input.scanTarget, input.config, {
        explicitCandidates: input.explicitCandidates,
      })
    : undefined;

  let report = await deps.runScan({
    version: input.version,
    scanTarget: input.scanTarget,
    config: input.config,
    flags: input.options,
    discoveryContext,
  });
  if (input.displayTarget && input.displayTarget !== report.scan_target) {
    report = {
      ...report,
      scan_target: input.displayTarget,
    };
  }
  const deepScanNotes: string[] = [];

  if (input.options.deep) {
    const discoverResources = deps.discoverDeepResources ?? (async () => []);
    const discoverLocalTextTargets = deps.discoverLocalTextTargets ?? (async () => []);
    const resources = await discoverResources(input.scanTarget, input.config, discoveryContext);
    const localTextTargets = await discoverLocalTextTargets(
      input.scanTarget,
      input.config,
      discoveryContext,
    );
    const optionsForAgent = deepAgentOptions(report, input.config);
    let selectedAgent: DeepAgentOption | null = null;

    if ((resources.length > 0 || localTextTargets.length > 0) && optionsForAgent.length > 0) {
      if (input.options.force || !interactivePromptsEnabled) {
        selectedAgent = optionsForAgent[0] ?? null;
      } else if (deps.requestDeepAgentSelection) {
        selectedAgent = await deps.requestDeepAgentSelection(optionsForAgent);
      }
    }

    if (resources.length === 0 && localTextTargets.length === 0) {
      deepScanNotes.push(...noEligibleDeepResourceNotes());
    } else {
      if (selectedAgent) {
        deepScanNotes.push(
          `Deep scan meta-agent selected: ${selectedAgent.label} (${selectedAgent.binary})`,
        );
      } else if (optionsForAgent.length > 0) {
        deepScanNotes.push(
          "Deep scan meta-agent skipped. Running deterministic Layer 3 checks only.",
        );
      } else {
        deepScanNotes.push(
          "No supported deep-scan agent detected (Claude Code, Codex CLI, or OpenCode). Running deterministic Layer 3 checks only.",
        );
      }

      if (resources.length > 0) {
        if (!deps.executeDeepResource) {
          throw new Error("Deep resource executor not configured");
        }

        let resourcesWithFetchedMetadata = 0;
        let executedMetaAgentCommands = 0;
        const outcomes = await runDeepScanWithConsent(
          resources,
          async (resource) => {
            if (input.options.force) {
              return true;
            }
            if (deps.requestDeepScanConsent) {
              return await deps.requestDeepScanConsent(resource);
            }
            return false;
          },
          async (resource) => {
            const fetched = await deps.executeDeepResource!(resource);
            if (fetched.status !== "ok" || !selectedAgent) {
              return fetched;
            }

            resourcesWithFetchedMetadata += 1;

            const prompt = buildSecurityAnalysisPrompt({
              resourceId: resource.id,
              resourceSummary: metadataSummary(fetched.metadata),
            });
            const command = buildMetaAgentCommand({
              tool: selectedAgent.metaTool,
              prompt,
              workingDirectory: input.scanTarget,
              binaryPath: selectedAgent.binary,
            });
            const commandContext: MetaAgentCommandConsentContext = {
              resource,
              agent: selectedAgent,
              command,
            };

            const approvedCommand =
              input.options.force ||
              (deps.requestMetaAgentCommandConsent
                ? await deps.requestMetaAgentCommandConsent(commandContext)
                : false);

            if (!approvedCommand) {
              return {
                ...fetched,
                metadata: withMetaAgentFinding(fetched.metadata, {
                  id: `layer3-meta-agent-skipped-${resource.id}`,
                  severity: "INFO",
                  description: `Deep scan meta-agent command skipped for ${resource.id}`,
                }),
              };
            }

            if (!deps.runMetaAgentCommand) {
              throw new Error("Meta-agent command runner not configured");
            }

            executedMetaAgentCommands += 1;
            const commandResult = await deps.runMetaAgentCommand(commandContext);
            if (commandResult.code !== 0) {
              return {
                ...fetched,
                metadata: withMetaAgentFinding(fetched.metadata, {
                  id: `layer3-meta-agent-command-error-${resource.id}`,
                  severity: "LOW",
                  description: `Deep scan meta-agent command failed for ${resource.id}`,
                  evidence: commandResult.stderr || `exit code: ${commandResult.code}`,
                }),
              };
            }

            const parsedOutput = parseMetaAgentOutput(commandResult.stdout);
            if (parsedOutput === null) {
              return {
                ...fetched,
                metadata: withMetaAgentFinding(fetched.metadata, {
                  id: `layer3-meta-agent-parse-error-${resource.id}`,
                  severity: "LOW",
                  description: `Deep scan meta-agent output was not valid JSON for ${resource.id}`,
                  evidence: commandResult.stdout.slice(0, 400),
                }),
              };
            }

            const normalizedOutput = Array.isArray(parsedOutput)
              ? { findings: parsedOutput }
              : parsedOutput;

            return {
              ...fetched,
              metadata: mergeMetaAgentMetadata(fetched.metadata, normalizedOutput),
            };
          },
        );

        const layer3Findings = layer3OutcomesToFindings(outcomes, {
          unicodeAnalysis: input.config.unicode_analysis,
        });
        report = mergeLayer3Findings(report, layer3Findings);

        if (selectedAgent) {
          if (resourcesWithFetchedMetadata === 0) {
            deepScanNotes.push(
              "Selected meta-agent was not executed because no approved resources returned metadata successfully.",
            );
          } else if (executedMetaAgentCommands === 0) {
            deepScanNotes.push(
              "Selected meta-agent was not executed because meta-agent command execution was not approved.",
            );
          } else {
            const suffix = executedMetaAgentCommands === 1 ? "" : "s";
            deepScanNotes.push(
              `Deep scan meta-agent executed for ${executedMetaAgentCommands} resource${suffix}.`,
            );
          }
        }
      }

      if (localTextTargets.length > 0) {
        if (!selectedAgent) {
          deepScanNotes.push(
            "Local instruction-file analysis skipped because no meta-agent was selected.",
          );
        } else if (!supportsToollessLocalTextAnalysis(selectedAgent.metaTool)) {
          deepScanNotes.push(
            "Local instruction-file analysis was skipped because the selected agent does not support tool-less analysis.",
          );
        } else {
          // Local instruction files are analyzed as inert text only; referenced URLs stay as evidence, not inputs.
          if (!deps.runMetaAgentCommand) {
            throw new Error("Meta-agent command runner not configured");
          }

          const isolatedWorkingDirectory = mkdtempSync(join(tmpdir(), "codegate-local-analysis-"));
          let executedLocalAnalyses = 0;
          try {
            for (const target of localTextTargets) {
              const prompt = buildLocalTextAnalysisPrompt({
                filePath: target.reportPath,
                textContent: buildPromptEvidenceText(target.textContent),
                referencedUrls: target.referencedUrls,
              });
              const command = buildMetaAgentCommand({
                tool: selectedAgent.metaTool,
                prompt,
                workingDirectory: isolatedWorkingDirectory,
                binaryPath: selectedAgent.binary,
              });
              command.timeoutMs = 60_000;
              const commandContext: MetaAgentCommandConsentContext = {
                localFile: target,
                agent: selectedAgent,
                command,
              };

              const approvedCommand =
                input.options.force ||
                (deps.requestMetaAgentCommandConsent
                  ? await deps.requestMetaAgentCommandConsent(commandContext)
                  : false);

              if (!approvedCommand) {
                continue;
              }

              executedLocalAnalyses += 1;
              const commandResult = await deps.runMetaAgentCommand(commandContext);
              if (commandResult.code !== 0) {
                deepScanNotes.push(
                  `Local instruction-file analysis failed for ${target.reportPath}: ${
                    commandResult.stderr || `exit code: ${commandResult.code}`
                  }`,
                );
                continue;
              }

              const parsedOutput = parseMetaAgentOutput(commandResult.stdout);
              if (parsedOutput === null) {
                deepScanNotes.push(
                  `Local instruction-file analysis returned invalid JSON for ${target.reportPath}.`,
                );
                continue;
              }

              const normalizedOutput = Array.isArray(parsedOutput)
                ? { findings: parsedOutput }
                : parsedOutput;
              const localFindings = parseLocalTextFindings(target.reportPath, normalizedOutput);
              report = mergeLayer3Findings(report, localFindings);
            }
          } finally {
            rmSync(isolatedWorkingDirectory, { recursive: true, force: true });
          }

          if (executedLocalAnalyses > 0) {
            const suffix = executedLocalAnalyses === 1 ? "" : "s";
            deepScanNotes.push(
              `Local instruction-file analysis executed for ${executedLocalAnalyses} file${suffix}.`,
            );
          }
        }
      }
    }
  }

  report = applyConfigPolicy(report, input.config);
  report = reorderRequestedTargetFindings(report, input.displayTarget);

  return {
    report,
    deepScanNotes,
  };
}

export async function executeScanCommand(
  input: ExecuteScanCommandInput,
  deps: ExecuteScanCommandDeps,
): Promise<void> {
  try {
    const interactivePromptsEnabled = deps.isTTY() && input.options.noTui !== true;
    const { report: analyzedReport, deepScanNotes } = await runScanAnalysis(input, {
      isTTY: deps.isTTY,
      runScan: deps.runScan,
      prepareScanDiscovery: deps.prepareScanDiscovery,
      discoverDeepResources: deps.discoverDeepResources,
      discoverLocalTextTargets: deps.discoverLocalTextTargets,
      requestDeepScanConsent: deps.requestDeepScanConsent,
      requestDeepAgentSelection: deps.requestDeepAgentSelection,
      requestMetaAgentCommandConsent: deps.requestMetaAgentCommandConsent,
      runMetaAgentCommand: deps.runMetaAgentCommand,
      executeDeepResource: deps.executeDeepResource,
    });
    let report = analyzedReport;
    const remediationRequested =
      input.options.remediate ||
      input.options.fixSafe ||
      input.options.dryRun ||
      input.options.patch;
    let remediationResult: RemediationRunnerResult | null = null;

    const executeRemediation = async (): Promise<void> => {
      if (!deps.runRemediation) {
        throw new Error("Remediation runner not configured");
      }
      const nextResult = await deps.runRemediation({
        scanTarget: input.scanTarget,
        report,
        config: input.config,
        flags: {
          remediate: input.options.remediate,
          fixSafe: input.options.fixSafe,
          dryRun: input.options.dryRun,
          patch: input.options.patch,
          output: input.options.output,
        },
        isTTY: deps.isTTY(),
      });
      remediationResult = nextResult;
      report = nextResult.report;
      if (nextResult.patchContent) {
        deps.stdout(nextResult.patchContent);
      }
      if (nextResult.patchPath) {
        deps.stdout(`Patch written: ${nextResult.patchPath}`);
      }
    };

    if (remediationRequested) {
      const beforeRemediation = report;
      const hasFixableFindings = report.summary.fixable > 0;
      if (
        !hasFixableFindings &&
        input.options.remediate === true &&
        input.options.fixSafe !== true &&
        input.options.dryRun !== true &&
        input.options.patch !== true
      ) {
        deps.stdout("No fixable findings available for remediation.");
      } else {
        const needsConsent =
          input.options.remediate === true &&
          input.options.dryRun !== true &&
          input.options.force !== true &&
          interactivePromptsEnabled &&
          hasFixableFindings;

        if (needsConsent) {
          const context: RemediationConsentContext = {
            scanTarget: input.scanTarget,
            totalFindings: report.summary.total,
            fixableFindings: report.summary.fixable,
            criticalFindings: report.summary.by_severity.CRITICAL ?? 0,
          };
          const approved = deps.requestRemediationConsent
            ? await deps.requestRemediationConsent(context)
            : false;
          if (approved) {
            await executeRemediation();
          } else {
            deps.stdout("Remediation skipped by user.");
          }
        } else {
          await executeRemediation();
        }

        if (remediationResult) {
          for (const line of remediationSummaryLines({
            scanTarget: input.scanTarget,
            options: input.options,
            before: beforeRemediation,
            result: remediationResult,
          })) {
            deps.stdout(line);
          }
        }
      }
    }

    const shouldUseTui =
      input.config.output_format === "terminal" &&
      input.config.tui.enabled &&
      !input.options.output &&
      deps.isTTY() &&
      deps.renderTui !== undefined;
    const targetSummaryNote =
      input.config.output_format === "terminal"
        ? summarizeRequestedTargetFindings(report, input.displayTarget)
        : null;
    const scanNotes =
      input.config.output_format === "terminal"
        ? targetSummaryNote
          ? [...deepScanNotes, targetSummaryNote]
          : deepScanNotes
        : [];

    if (shouldUseTui) {
      deps.renderTui?.({ view: "dashboard", report, notices: scanNotes });
      deps.renderTui?.({ view: "summary", report });
    } else {
      if (scanNotes.length > 0) {
        for (const note of scanNotes) {
          deps.stdout(note);
        }
      }
      const rendered = renderByFormat(input.config.output_format, report, {
        verbose: input.options.verbose,
      });
      if (input.options.output) {
        deps.writeFile(resolve(input.cwd, input.options.output), rendered);
      } else {
        deps.stdout(rendered);
      }
    }
    deps.setExitCode(report.summary.exit_code);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    deps.stderr(`Scan failed: ${message}`);
    deps.setExitCode(3);
  }
}
