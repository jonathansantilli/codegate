import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { collectUntrustedReachableJobIds } from "../workflow/analysis.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowPrTargetCheckoutHeadInput {
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

function isCheckoutStep(uses: string | undefined): boolean {
  if (!uses) {
    return false;
  }
  return /^actions\/checkout(?:@.+)?$/iu.test(uses.trim());
}

function isRiskyCheckoutRef(ref: string | undefined): boolean {
  if (!ref) {
    return false;
  }
  const normalized = ref.toLowerCase();
  return (
    normalized.includes("github.event.pull_request.head.") || normalized.includes("github.head_ref")
  );
}

function hasInheritedSecrets(secrets: unknown): boolean {
  return typeof secrets === "string" && secrets.trim().toLowerCase() === "inherit";
}

export function detectWorkflowPrTargetCheckoutHead(
  input: WorkflowPrTargetCheckoutHeadInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const hasPullRequestTarget = facts.triggers.some(
    (trigger) => trigger.trim().toLowerCase() === "pull_request_target",
  );
  if (!hasPullRequestTarget) {
    return [];
  }

  const reachableJobIds = collectUntrustedReachableJobIds(facts);
  if (reachableJobIds.size === 0) {
    return [];
  }

  const findings: Finding[] = [];
  const workflowPrivileged = hasWritePermission(facts.workflowPermissions);

  facts.jobs.forEach((job, jobIndex) => {
    if (!reachableJobIds.has(job.id)) {
      return;
    }

    const jobPrivileged =
      workflowPrivileged || hasWritePermission(job.permissions) || hasInheritedSecrets(job.secrets);

    job.steps.forEach((step, stepIndex) => {
      if (!isCheckoutStep(step.uses)) {
        return;
      }
      if (!isRiskyCheckoutRef(step.with?.ref)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [
          "pull_request_target",
          "actions/checkout",
          step.with?.ref ?? "github.event.pull_request.head",
        ],
        fallbackValue: "pull_request_target workflow checks out untrusted PR head ref",
      });

      findings.push({
        rule_id: "workflow-pr-target-checkout-head",
        finding_id: `WORKFLOW_PR_TARGET_CHECKOUT_HEAD-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: jobPrivileged ? "CRITICAL" : "HIGH",
        category: "CI_TRIGGER",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].with.ref` },
        description:
          "pull_request_target job checks out pull request head ref, enabling untrusted code execution in privileged context",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-284",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Avoid checking out pull request head refs in pull_request_target workflows",
          "Use pull_request for untrusted code validation and keep privileged operations isolated",
          "Enforce least-privilege token scopes and avoid inherited secrets for untrusted paths",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
