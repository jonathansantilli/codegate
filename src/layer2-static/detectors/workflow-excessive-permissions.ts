import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowExcessivePermissionsInput {
  filePath: string;
  parsed: unknown;
}

function hasWritePermission(value: unknown): boolean {
  if (typeof value === "string") {
    return value === "write-all";
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  return Object.values(value as Record<string, unknown>).some(
    (permission) => permission === "write",
  );
}

export function detectWorkflowExcessivePermissions(
  input: WorkflowExcessivePermissionsInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  if (hasWritePermission(facts.workflowPermissions)) {
    findings.push({
      rule_id: "workflow-excessive-permissions",
      finding_id: `WORKFLOW_EXCESSIVE_PERMISSIONS-WORKFLOW-${input.filePath}`,
      severity: "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: "permissions" },
      description: "Workflow defines overly broad write permissions",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-732",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: ["Scope GITHUB_TOKEN permissions to least privilege"],
      evidence: typeof facts.workflowPermissions === "string" ? facts.workflowPermissions : null,
      suppressed: false,
    });
  }

  facts.jobs.forEach((job, index) => {
    if (!hasWritePermission(job.permissions)) {
      return;
    }

    findings.push({
      rule_id: "workflow-excessive-permissions",
      finding_id: `WORKFLOW_EXCESSIVE_PERMISSIONS-JOB-${input.filePath}-${index}`,
      severity: "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${job.id}.permissions` },
      description: "Job defines overly broad write permissions",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-732",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: ["Reduce job-level permissions to required read scopes"],
      suppressed: false,
    });
  });

  return findings;
}
