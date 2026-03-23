import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { collectUntrustedReachableJobIds } from "../workflow/analysis.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowLocalActionMutationInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function hasWritePermission(value: unknown): boolean {
  if (typeof value === "string") {
    return value.trim().toLowerCase() === "write-all";
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  return Object.values(value as Record<string, unknown>).some((permission) => {
    if (typeof permission !== "string") {
      return false;
    }
    return permission.trim().toLowerCase() === "write";
  });
}

function hasIdTokenWrite(value: unknown): boolean {
  if (typeof value === "string") {
    return value.trim().toLowerCase() === "write-all";
  }
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

function isLocalUsesReference(value: string | undefined): boolean {
  if (!value) {
    return false;
  }
  const normalized = value.trim();
  return normalized.startsWith("./") || normalized.startsWith(".\\");
}

export function detectWorkflowLocalActionMutation(
  input: WorkflowLocalActionMutationInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const reachableJobIds = collectUntrustedReachableJobIds(facts);
  if (reachableJobIds.size === 0) {
    return [];
  }

  const findings: Finding[] = [];
  const workflowPrivileged =
    hasWritePermission(facts.workflowPermissions) || hasIdTokenWrite(facts.workflowPermissions);

  facts.jobs.forEach((job, jobIndex) => {
    if (!reachableJobIds.has(job.id)) {
      return;
    }

    const jobPrivileged =
      workflowPrivileged ||
      hasWritePermission(job.permissions) ||
      hasIdTokenWrite(job.permissions) ||
      hasInheritedSecrets(job.secrets);
    const severity = jobPrivileged ? "HIGH" : "MEDIUM";

    if (isLocalUsesReference(job.uses)) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [job.uses ?? "", "uses: ./", "pull_request_target"],
        fallbackValue: `${job.id} invokes local reusable workflow in untrusted context`,
      });

      findings.push({
        rule_id: "workflow-local-action-mutation",
        finding_id: `WORKFLOW_LOCAL_ACTION_MUTATION-JOB-${input.filePath}-${jobIndex}`,
        severity,
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.uses` },
        description:
          "Untrusted workflow path executes a local reusable workflow reference that can be mutated by pull request content",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-494",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Avoid executing local reusable workflows from untrusted trigger contexts",
          "Move privileged operations to immutable pinned actions or trusted workflow_call boundaries",
          "Use read-only contexts when local action references are unavoidable",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    }

    job.steps.forEach((step, stepIndex) => {
      if (!isLocalUsesReference(step.uses)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [step.uses ?? "", "uses: ./", "pull_request_target"],
        fallbackValue: `${job.id} executes mutable local action from untrusted context`,
      });

      findings.push({
        rule_id: "workflow-local-action-mutation",
        finding_id: `WORKFLOW_LOCAL_ACTION_MUTATION-STEP-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity,
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].uses` },
        description:
          "Untrusted workflow path executes a local action reference that can be modified by the same pull request",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-494",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Avoid local action execution in untrusted trigger workflows with privileged permissions",
          "Pin to immutable third-party actions or split untrusted and privileged jobs",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
