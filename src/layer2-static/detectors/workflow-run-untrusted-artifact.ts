import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowRunUntrustedArtifactInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function hasWritePermission(value: unknown): boolean {
  if (typeof value === "string") {
    return value.trim().toLowerCase() === "write-all";
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  return Object.values(value as Record<string, unknown>).some(
    (permission) => typeof permission === "string" && permission.trim().toLowerCase() === "write",
  );
}

function hasIdTokenWrite(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const idTokenPermission = (value as Record<string, unknown>)["id-token"];
  return (
    typeof idTokenPermission === "string" && idTokenPermission.trim().toLowerCase() === "write"
  );
}

function hasInheritedSecrets(secrets: unknown): boolean {
  return typeof secrets === "string" && secrets.trim().toLowerCase() === "inherit";
}

function hasWorkflowRunBranchFilter(parsed: unknown): boolean {
  const root = asRecord(parsed);
  const onValue = asRecord(root?.on);
  const workflowRun = asRecord(onValue?.workflow_run);
  if (!workflowRun) {
    return false;
  }

  const branches = workflowRun.branches;
  if (typeof branches === "string") {
    return branches.trim().length > 0;
  }
  if (!Array.isArray(branches)) {
    return false;
  }

  return branches.some((branch) => typeof branch === "string" && branch.trim().length > 0);
}

function hasWorkflowRunOriginGuard(condition: string | undefined): boolean {
  if (typeof condition !== "string") {
    return false;
  }

  return /github\.event\.workflow_run\.event\s*!=\s*['"]pull_request['"]/iu.test(condition);
}

function hasWorkflowRunBranchGuard(condition: string | undefined): boolean {
  if (typeof condition !== "string") {
    return false;
  }

  return /\bgithub\.event\.workflow_run\.head_branch\b/iu.test(condition);
}

function isDownloadArtifactStep(stepUses: string | undefined): boolean {
  if (typeof stepUses !== "string") {
    return false;
  }
  return /^actions\/download-artifact@/iu.test(stepUses.trim());
}

export function detectWorkflowRunUntrustedArtifact(
  input: WorkflowRunUntrustedArtifactInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (
    !facts ||
    !facts.triggers.some((trigger) => trigger.trim().toLowerCase() === "workflow_run")
  ) {
    return [];
  }

  const workflowHasBranchFilter = hasWorkflowRunBranchFilter(input.parsed);
  const workflowHasWritePermission = hasWritePermission(facts.workflowPermissions);

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    const hasArtifactDownload = job.steps.some((step) => isDownloadArtifactStep(step.uses));
    if (!hasArtifactDownload) {
      return;
    }

    const hasRunExecution = job.steps.some(
      (step) => typeof step.run === "string" && step.run.trim().length > 0,
    );
    if (!hasRunExecution) {
      return;
    }

    const hasPrivilegedContext =
      workflowHasWritePermission ||
      hasWritePermission(job.permissions) ||
      hasIdTokenWrite(facts.workflowPermissions) ||
      hasIdTokenWrite(job.permissions) ||
      hasInheritedSecrets(job.secrets);
    if (!hasPrivilegedContext) {
      return;
    }

    const hasOriginGuard = hasWorkflowRunOriginGuard(job.if);
    const hasBranchGuard = workflowHasBranchFilter || hasWorkflowRunBranchGuard(job.if);
    if (hasOriginGuard && hasBranchGuard) {
      return;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: ["workflow_run", "actions/download-artifact", "github.event.workflow_run.event"],
      fallbackValue: `${job.id} consumes workflow_run artifacts in privileged context without strict guards`,
    });

    findings.push({
      rule_id: "workflow-run-untrusted-artifact",
      finding_id: `WORKFLOW_RUN_UNTRUSTED_ARTIFACT-${input.filePath}-${jobIndex}`,
      severity: "HIGH",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${job.id}` },
      description:
        "Privileged workflow_run job downloads artifacts and executes commands without strict origin and branch guards",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-829",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Guard workflow_run jobs with github.event.workflow_run.event != 'pull_request'",
        "Restrict workflow_run execution to trusted branches and validate artifact contents before use",
        "Download artifacts into temporary directories and avoid executing untrusted artifact content directly",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  });

  return findings;
}
