import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowUnsoundContainsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface StepCondition {
  jobId: string;
  stepIndex: number;
  condition: string;
  run?: string;
}

const PRIVILEGED_COMMANDS = ["publish", "deploy", "release", "gh release"];
const UNTRUSTED_CONTAINS_PATTERNS = [
  /contains\s*\(\s*github\.event\.pull_request\.(?:title|body)/iu,
  /contains\s*\(\s*github\.event\.comment\.body/iu,
  /contains\s*\(\s*github\.event\.issue\.title/iu,
];

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
      if (!step || typeof step.if !== "string") {
        return;
      }
      candidates.push({
        jobId,
        stepIndex,
        condition: step.if,
        run: typeof step.run === "string" ? step.run : undefined,
      });
    });
  }
  return candidates;
}

function isUnsoundContains(condition: string): boolean {
  return UNTRUSTED_CONTAINS_PATTERNS.some((pattern) => pattern.test(condition));
}

function isPrivilegedStep(run: string | undefined): boolean {
  const normalized = run?.toLowerCase() ?? "";
  return PRIVILEGED_COMMANDS.some((command) => normalized.includes(command));
}

export function detectWorkflowUnsoundContains(input: WorkflowUnsoundContainsInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  for (const candidate of gatherStepConditions(input.parsed)) {
    if (!isUnsoundContains(candidate.condition) || !isPrivilegedStep(candidate.run)) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [candidate.condition, candidate.run ?? ""],
      fallbackValue: candidate.condition,
    });

    findings.push({
      rule_id: "workflow-unsound-contains",
      finding_id: `WORKFLOW_UNSOUND_CONTAINS-${input.filePath}-${candidate.jobId}-${candidate.stepIndex}`,
      severity: "HIGH",
      category: "CI_TRIGGER",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${candidate.jobId}.steps[${candidate.stepIndex}].if` },
      description: "Workflow gates a privileged step with contains() over untrusted event content",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-20",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Avoid trust decisions based on contains() over untrusted titles, bodies, or comments",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
