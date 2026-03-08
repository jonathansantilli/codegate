import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { applyConfigPolicy, type CodeGateConfig } from "../config.js";
import type { DiscoveryFormat } from "../types/discovery.js";
import type { Finding } from "../types/finding.js";
import type { CodeGateReport } from "../types/report.js";
import { createBackupSession } from "./backup-manager.js";
import { generateUnifiedDiff } from "./diff-generator.js";
import {
  applyRemediationAction,
  planRemediation,
  type RemediationFile,
  type RemediationPlanItem,
} from "./remediator.js";

export interface RemediationFlags {
  remediate?: boolean;
  fixSafe?: boolean;
  dryRun?: boolean;
  patch?: boolean;
  output?: string;
}

export interface RemediationRunnerInput {
  scanTarget: string;
  report: CodeGateReport;
  config: CodeGateConfig;
  flags: RemediationFlags;
  isTTY: boolean;
}

export interface RemediationRunnerResult {
  report: CodeGateReport;
  plannedCount: number;
  appliedCount: number;
  plannedActions?: Array<{
    findingId: string;
    filePath: string;
    action: RemediationPlanItem["action"]["type"];
  }>;
  appliedActions?: Array<{
    findingId: string;
    filePath: string;
    action: RemediationPlanItem["action"]["type"];
  }>;
  backupSessionId?: string;
  patchContent?: string;
  patchPath?: string;
}

function inferFormat(filePath: string): DiscoveryFormat {
  if (filePath.endsWith(".json")) {
    return "json";
  }
  if (filePath.endsWith(".jsonc")) {
    return "jsonc";
  }
  if (filePath.endsWith(".toml")) {
    return "toml";
  }
  if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) {
    return "yaml";
  }
  if (filePath.endsWith(".env")) {
    return "dotenv";
  }
  if (filePath.endsWith(".md") || filePath.endsWith(".mdc")) {
    return "markdown";
  }
  return "text";
}

function loadRemediationFiles(scanTarget: string, report: CodeGateReport): RemediationFile[] {
  const uniquePaths = Array.from(
    new Set(
      report.findings.flatMap((finding) => {
        const paths = [finding.file_path];
        if (finding.source_config?.file_path) {
          paths.push(finding.source_config.file_path);
        }
        return paths;
      }),
    ),
  );
  const files: RemediationFile[] = [];

  for (const relativePath of uniquePaths) {
    const absolutePath = resolve(scanTarget, relativePath);
    if (!existsSync(absolutePath)) {
      continue;
    }
    files.push({
      path: relativePath,
      format: inferFormat(relativePath),
      content: readFileSync(absolutePath, "utf8"),
    });
  }

  return files;
}

function isSafeCriticalPlan(plan: RemediationPlanItem, report: CodeGateReport): boolean {
  const finding = report.findings.find((item) => item.finding_id === plan.findingId);
  if (!finding || finding.severity !== "CRITICAL") {
    return false;
  }
  return plan.action.type === "remove_field" || plan.action.type === "replace_value";
}

function choosePlans(
  input: RemediationRunnerInput,
  plans: RemediationPlanItem[],
): RemediationPlanItem[] {
  if (input.flags.fixSafe) {
    return plans.filter((plan) => isSafeCriticalPlan(plan, input.report));
  }
  return plans;
}

function toPatchContent(plans: RemediationPlanItem[]): string {
  return plans
    .map((plan) => plan.diff)
    .filter((diff) => diff.length > 0)
    .join("\n\n");
}

function toActionSummaries(
  plans: RemediationPlanItem[],
): RemediationRunnerResult["plannedActions"] {
  return plans.map((plan) => ({
    findingId: plan.findingId,
    filePath: plan.filePath,
    action: plan.action.type,
  }));
}

function findingById(report: CodeGateReport): Map<string, Finding> {
  return new Map(report.findings.map((finding) => [finding.finding_id, finding] as const));
}

function composeRemediationPlans(
  report: CodeGateReport,
  files: RemediationFile[],
  selectedPlans: RemediationPlanItem[],
): RemediationPlanItem[] {
  const filesByPath = new Map(files.map((file) => [file.path, file] as const));
  const findings = findingById(report);
  const plansByFile = new Map<string, RemediationPlanItem[]>();

  for (const plan of selectedPlans) {
    const grouped = plansByFile.get(plan.filePath);
    if (grouped) {
      grouped.push(plan);
      continue;
    }
    plansByFile.set(plan.filePath, [plan]);
  }

  const composedPlans: RemediationPlanItem[] = [];

  for (const [filePath, plans] of plansByFile.entries()) {
    const file = filesByPath.get(filePath);
    if (!file) {
      continue;
    }

    const quarantinePlan = plans.find((plan) => plan.action.type === "quarantine");
    if (quarantinePlan) {
      const finding = findings.get(quarantinePlan.findingId);
      if (!finding) {
        continue;
      }
      const result = applyRemediationAction(quarantinePlan.action, file, finding);
      if (!result.changed) {
        continue;
      }
      composedPlans.push(
        ...plans.map((plan) => ({
          findingId: plan.findingId,
          filePath,
          action: { type: "quarantine" } as const,
          originalContent: file.content,
          updatedContent: result.updatedContent,
          diff: generateUnifiedDiff({
            filePath,
            before: file.content,
            after: result.updatedContent,
          }),
        })),
      );
      continue;
    }

    let workingFile: RemediationFile = { ...file };
    const appliedPlans: RemediationPlanItem[] = [];
    const structuredPlans = plans.filter(
      (plan) => plan.action.type === "remove_field" || plan.action.type === "replace_value",
    );
    const textPlans = plans.filter((plan) => plan.action.type === "strip_unicode");

    for (const plan of [...structuredPlans, ...textPlans]) {
      const finding = findings.get(plan.findingId);
      if (!finding) {
        continue;
      }
      const result = applyRemediationAction(plan.action, workingFile, finding);
      if (!result.changed) {
        continue;
      }
      const before = workingFile.content;
      workingFile = {
        ...workingFile,
        content: result.updatedContent,
      };
      appliedPlans.push({
        findingId: plan.findingId,
        filePath,
        action: plan.action,
        originalContent: before,
        updatedContent: result.updatedContent,
        diff: generateUnifiedDiff({
          filePath,
          before,
          after: result.updatedContent,
        }),
      });
    }

    composedPlans.push(...appliedPlans);
  }

  return composedPlans;
}

export function runRemediation(input: RemediationRunnerInput): RemediationRunnerResult {
  const remediationEnabled =
    input.flags.remediate || input.flags.fixSafe || input.flags.patch || input.flags.dryRun;
  if (!remediationEnabled) {
    return {
      report: input.report,
      plannedCount: 0,
      appliedCount: 0,
    };
  }

  const files = loadRemediationFiles(input.scanTarget, input.report);
  const plans = planRemediation({
    findings: input.report.findings,
    files,
  });
  const selectedPlans = choosePlans(input, plans);
  const composedPlans = composeRemediationPlans(input.report, files, selectedPlans);
  const patchContent = toPatchContent(composedPlans);

  let patchPath: string | undefined;
  if (input.flags.patch) {
    if (input.flags.output) {
      patchPath = resolve(input.scanTarget, input.flags.output);
      writeFileSync(patchPath, patchContent, "utf8");
    } else if (input.isTTY) {
      patchPath = resolve(input.scanTarget, "codegate-fixes.patch");
      writeFileSync(patchPath, patchContent, "utf8");
    }
  }

  if (input.flags.dryRun || (!input.flags.remediate && !input.flags.fixSafe)) {
    return {
      report: input.report,
      plannedCount: composedPlans.length,
      appliedCount: 0,
      plannedActions: toActionSummaries(composedPlans),
      appliedActions: [],
      patchContent:
        input.flags.patch && !input.flags.output && !input.isTTY ? patchContent : undefined,
      patchPath,
    };
  }

  const filePlans = new Map<string, RemediationPlanItem>();
  for (const plan of composedPlans) {
    if (!filePlans.has(plan.filePath)) {
      filePlans.set(plan.filePath, plan);
      continue;
    }
    filePlans.set(plan.filePath, {
      ...plan,
      originalContent: filePlans.get(plan.filePath)?.originalContent ?? plan.originalContent,
    });
  }

  const session = createBackupSession({
    projectRoot: input.scanTarget,
    version: input.report.version,
    filePaths: Array.from(filePlans.keys()),
  });

  for (const plan of filePlans.values()) {
    writeFileSync(resolve(input.scanTarget, plan.filePath), plan.updatedContent, "utf8");
  }

  const appliedFindings = new Set(composedPlans.map((plan) => plan.findingId));
  const remainingFindings = input.report.findings.filter(
    (finding) => !appliedFindings.has(finding.finding_id),
  );

  const report = applyConfigPolicy(
    {
      ...input.report,
      findings: remainingFindings,
    },
    input.config,
  );

  return {
    report,
    plannedCount: composedPlans.length,
    appliedCount: composedPlans.length,
    plannedActions: toActionSummaries(composedPlans),
    appliedActions: toActionSummaries(composedPlans),
    backupSessionId: session.sessionId,
    patchContent:
      input.flags.patch && !input.flags.output && !input.isTTY ? patchContent : undefined,
    patchPath,
  };
}
