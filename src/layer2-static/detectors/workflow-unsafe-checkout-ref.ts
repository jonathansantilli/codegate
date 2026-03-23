import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowUnsafeCheckoutRefInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const UNTRUSTED_REF_PATTERNS = [
  /\bgithub\.event\.pull_request\.head\.ref\b/iu,
  /\bgithub\.head_ref\b/iu,
  /\bgithub\.event\.workflow_run\.head_branch\b/iu,
];

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

function isCheckoutStep(stepUses: string | undefined): boolean {
  if (typeof stepUses !== "string") {
    return false;
  }
  return /^actions\/checkout@/iu.test(stepUses.trim());
}

function hasUnsafeRef(ref: string | undefined): boolean {
  if (typeof ref !== "string") {
    return false;
  }
  return UNTRUSTED_REF_PATTERNS.some((pattern) => pattern.test(ref));
}

export function detectWorkflowUnsafeCheckoutRef(input: WorkflowUnsafeCheckoutRefInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const hasRelevantTrigger = facts.triggers.some((trigger) => {
    const normalized = trigger.trim().toLowerCase();
    return normalized === "pull_request_target" || normalized === "workflow_run";
  });
  if (!hasRelevantTrigger) {
    return [];
  }

  const workflowPrivileged =
    hasWritePermission(facts.workflowPermissions) || hasIdTokenWrite(facts.workflowPermissions);
  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    const jobPrivileged =
      workflowPrivileged ||
      hasWritePermission(job.permissions) ||
      hasIdTokenWrite(job.permissions) ||
      hasInheritedSecrets(job.secrets);
    if (!jobPrivileged) {
      return;
    }

    job.steps.forEach((step, stepIndex) => {
      if (!isCheckoutStep(step.uses)) {
        return;
      }

      const refValue = step.with?.ref;
      if (!hasUnsafeRef(refValue)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [step.uses ?? "", refValue ?? "", "head.ref", "head_branch"],
        fallbackValue: `jobs.${job.id}.steps[${stepIndex}].with.ref`,
      });

      findings.push({
        rule_id: "workflow-unsafe-checkout-ref",
        finding_id: `WORKFLOW_UNSAFE_CHECKOUT_REF-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_TEMPLATE_INJECTION",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].with.ref` },
        description:
          "Privileged checkout references attacker-influenced ref names; prefer immutable commit SHA values",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-20",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Use github.event.pull_request.head.sha (or an immutable SHA) instead of head.ref/head_branch values",
          "Avoid checking out attacker-controlled refs in privileged workflows",
        ],
        evidence: evidence?.evidence ?? refValue ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
