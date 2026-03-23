import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowMisfeatureInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface StepCandidate {
  jobId: string;
  stepIndex: number;
  name?: string;
  run?: string;
  uses?: string;
  continueOnError: boolean;
}

const SECURITY_TOKENS = [
  "codeql",
  "security",
  "sast",
  "secret",
  "dependency review",
  "npm audit",
  "trivy",
];

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function isContinueOnErrorEnabled(value: unknown): boolean {
  if (value === true) {
    return true;
  }
  return typeof value === "string" && value.trim().toLowerCase() === "true";
}

function isSecurityStep(candidate: StepCandidate): boolean {
  const combined = [candidate.name, candidate.run, candidate.uses]
    .filter((value): value is string => typeof value === "string")
    .join(" ")
    .toLowerCase();
  return SECURITY_TOKENS.some((token) => combined.includes(token));
}

function gatherCandidates(parsed: unknown): StepCandidate[] {
  const root = asRecord(parsed);
  const jobs = asRecord(root?.jobs);
  if (!jobs) {
    return [];
  }

  const candidates: StepCandidate[] = [];
  for (const [jobId, jobValue] of Object.entries(jobs)) {
    const job = asRecord(jobValue);
    const steps = Array.isArray(job?.steps) ? job.steps : [];
    steps.forEach((stepValue, stepIndex) => {
      const step = asRecord(stepValue);
      if (!step) {
        return;
      }
      candidates.push({
        jobId,
        stepIndex,
        name: typeof step.name === "string" ? step.name : undefined,
        run: typeof step.run === "string" ? step.run : undefined,
        uses: typeof step.uses === "string" ? step.uses : undefined,
        continueOnError: isContinueOnErrorEnabled(step["continue-on-error"]),
      });
    });
  }

  return candidates;
}

export function detectWorkflowMisfeature(input: WorkflowMisfeatureInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  for (const candidate of gatherCandidates(input.parsed)) {
    if (!candidate.continueOnError || !isSecurityStep(candidate)) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: ["continue-on-error: true", candidate.run ?? "", candidate.name ?? ""],
      fallbackValue: "security step continues on error",
    });

    findings.push({
      rule_id: "workflow-misfeature",
      finding_id: `WORKFLOW_MISFEATURE-${input.filePath}-${candidate.jobId}-${candidate.stepIndex}`,
      severity: "MEDIUM",
      category: "CI_TRIGGER",
      layer: "L2",
      file_path: input.filePath,
      location: {
        field: `jobs.${candidate.jobId}.steps[${candidate.stepIndex}].continue-on-error`,
      },
      description:
        "Security-relevant step is configured with continue-on-error, which can hide failed checks",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-703",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Remove continue-on-error from security-critical steps or split non-blocking diagnostics into separate jobs",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
