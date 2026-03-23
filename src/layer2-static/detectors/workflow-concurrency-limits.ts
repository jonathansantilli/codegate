import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowConcurrencyLimitsInput {
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

function hasRiskyTrigger(triggers: string[]): boolean {
  return triggers.some(
    (trigger) =>
      trigger === "pull_request_target" ||
      trigger === "workflow_run" ||
      trigger === "issue_comment",
  );
}

function hasWorkflowConcurrency(parsed: unknown): boolean {
  const root = asRecord(parsed);
  const concurrency = root?.concurrency;
  if (typeof concurrency === "string") {
    return concurrency.trim().length > 0;
  }
  return asRecord(concurrency) !== null;
}

function hasAnyJobConcurrency(parsed: unknown): boolean {
  const root = asRecord(parsed);
  const jobs = asRecord(root?.jobs);
  if (!jobs) {
    return false;
  }
  return Object.values(jobs).some((jobValue) => {
    const job = asRecord(jobValue);
    const concurrency = job?.concurrency;
    if (typeof concurrency === "string") {
      return concurrency.trim().length > 0;
    }
    return asRecord(concurrency) !== null;
  });
}

export function detectWorkflowConcurrencyLimits(input: WorkflowConcurrencyLimitsInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts || !hasRiskyTrigger(facts.triggers)) {
    return [];
  }

  if (hasWorkflowConcurrency(input.parsed) || hasAnyJobConcurrency(input.parsed)) {
    return [];
  }

  const evidence = buildFindingEvidence({
    textContent: input.textContent,
    searchTerms: ["pull_request_target", "workflow_run", "issue_comment", "concurrency"],
    fallbackValue: "risky trigger without concurrency limits",
  });

  return [
    {
      rule_id: "workflow-concurrency-limits",
      finding_id: `WORKFLOW_CONCURRENCY_LIMITS-${input.filePath}`,
      severity: "MEDIUM",
      category: "CI_TRIGGER",
      layer: "L2",
      file_path: input.filePath,
      location: { field: "concurrency" },
      description:
        "Workflow uses risky triggers without concurrency controls, increasing race and replay risk",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-362",
      confidence: "MEDIUM",
      fixable: false,
      remediation_actions: [
        "Define workflow- or job-level concurrency groups with cancel-in-progress controls",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    },
  ];
}
