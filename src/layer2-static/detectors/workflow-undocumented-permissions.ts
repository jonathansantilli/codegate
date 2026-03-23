import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowUndocumentedPermissionsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function isWritePermission(value: unknown): boolean {
  if (typeof value === "string") {
    return value === "write" || value === "write-all";
  }
  return false;
}

function lineContaining(textContent: string, term: string): string | null {
  const lines = textContent.split(/\r?\n/u);
  for (const line of lines) {
    if (line.includes(term)) {
      return line;
    }
  }
  return null;
}

function hasLineComment(textContent: string, term: string): boolean {
  const line = lineContaining(textContent, term);
  return line ? line.includes("#") : false;
}

function pushPermissionFinding(
  findings: Finding[],
  input: WorkflowUndocumentedPermissionsInput,
  field: string,
  evidenceTerm: string,
  description: string,
  permissionValue: string,
): void {
  const evidence = buildFindingEvidence({
    textContent: input.textContent,
    searchTerms: [evidenceTerm, permissionValue],
    fallbackValue: evidenceTerm,
  });

  findings.push({
    rule_id: "workflow-undocumented-permissions",
    finding_id: `WORKFLOW_UNDOCUMENTED_PERMISSIONS-${input.filePath}-${field}`,
    severity: "HIGH",
    category: "CI_PERMISSIONS",
    layer: "L2",
    file_path: input.filePath,
    location: { field },
    description,
    affected_tools: ["github-actions"],
    cve: null,
    owasp: ["ASI02"],
    cwe: "CWE-732",
    confidence: "MEDIUM",
    fixable: false,
    remediation_actions: [
      "Document why elevated permissions are required or reduce the permission scope",
    ],
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  });
}

export function detectWorkflowUndocumentedPermissions(
  input: WorkflowUndocumentedPermissionsInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  if (typeof facts.workflowPermissions === "string") {
    const value = facts.workflowPermissions.trim().toLowerCase();
    if (
      (value === "write-all" || value === "write") &&
      !hasLineComment(input.textContent, "permissions:")
    ) {
      pushPermissionFinding(
        findings,
        input,
        "permissions",
        `permissions: ${facts.workflowPermissions}`,
        "Workflow defines elevated permissions without documenting why they are needed",
        `permissions: ${facts.workflowPermissions}`,
      );
    }
  } else if (facts.workflowPermissions && typeof facts.workflowPermissions === "object") {
    for (const [scope, value] of Object.entries(facts.workflowPermissions)) {
      if (!isWritePermission(value)) {
        continue;
      }
      const term = `${scope}: ${value}`;
      if (hasLineComment(input.textContent, term)) {
        continue;
      }
      pushPermissionFinding(
        findings,
        input,
        `permissions.${scope}`,
        term,
        "Workflow defines elevated permissions without documenting why they are needed",
        term,
      );
    }
  }

  facts.jobs.forEach((job) => {
    if (typeof job.permissions === "string") {
      const value = job.permissions.trim().toLowerCase();
      if (value === "write-all" && !hasLineComment(input.textContent, "permissions:")) {
        pushPermissionFinding(
          findings,
          input,
          `jobs.${job.id}.permissions`,
          `permissions: ${job.permissions}`,
          "Job defines elevated permissions without documenting why they are needed",
          `permissions: ${job.permissions}`,
        );
      }
      return;
    }

    if (!job.permissions || typeof job.permissions !== "object") {
      return;
    }

    for (const [scope, value] of Object.entries(job.permissions)) {
      if (!isWritePermission(value)) {
        continue;
      }

      const term = `${scope}: ${value}`;
      if (hasLineComment(input.textContent, term)) {
        continue;
      }

      pushPermissionFinding(
        findings,
        input,
        `jobs.${job.id}.permissions.${scope}`,
        term,
        "Job defines elevated permissions without documenting why they are needed",
        term,
      );
    }
  });

  return findings;
}
