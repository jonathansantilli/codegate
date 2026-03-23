import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowUnsoundConditionInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface StepCondition {
  jobId: string;
  stepIndex: number;
  condition: string;
  run?: string;
  uses?: string;
}

const SENSITIVE_COMMANDS = ["publish", "deploy", "release", "push"];

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function gatherStepConditions(parsed: unknown): StepCondition[] {
  const root = asRecord(parsed);
  const jobs = asRecord(root?.jobs);
  if (!jobs) {
    return [];
  }

  const candidates: StepCondition[] = [];
  for (const [jobId, jobValue] of Object.entries(jobs)) {
    const job = asRecord(jobValue);
    const steps = Array.isArray(job?.steps) ? job.steps : [];
    steps.forEach((stepValue, stepIndex) => {
      const step = asRecord(stepValue);
      const condition = typeof step?.if === "string" ? step.if : undefined;
      if (!condition) {
        return;
      }
      candidates.push({
        jobId,
        stepIndex,
        condition,
        run: typeof step?.run === "string" ? step.run : undefined,
        uses: typeof step?.uses === "string" ? step.uses : undefined,
      });
    });
  }

  return candidates;
}

function isAlwaysCondition(condition: string): boolean {
  const normalized = condition.toLowerCase();
  return normalized.includes("always()");
}

function isSensitiveExecution(run: string | undefined, uses: string | undefined): boolean {
  const runValue = run?.toLowerCase() ?? "";
  if (SENSITIVE_COMMANDS.some((token) => runValue.includes(token))) {
    return true;
  }

  return typeof uses === "string" && uses.trim().length > 0;
}

export function detectWorkflowUnsoundCondition(input: WorkflowUnsoundConditionInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  for (const candidate of gatherStepConditions(input.parsed)) {
    if (
      !isAlwaysCondition(candidate.condition) ||
      !isSensitiveExecution(candidate.run, candidate.uses)
    ) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [candidate.condition, candidate.run ?? "", candidate.uses ?? ""],
      fallbackValue: candidate.condition,
    });

    findings.push({
      rule_id: "workflow-unsound-condition",
      finding_id: `WORKFLOW_UNSOUND_CONDITION-${input.filePath}-${candidate.jobId}-${candidate.stepIndex}`,
      severity: "MEDIUM",
      category: "CI_TRIGGER",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${candidate.jobId}.steps[${candidate.stepIndex}].if` },
      description:
        "Workflow uses always() on a sensitive step, which can bypass expected failure gating",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-754",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Replace always() with explicit success and trust-boundary checks for sensitive steps",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
