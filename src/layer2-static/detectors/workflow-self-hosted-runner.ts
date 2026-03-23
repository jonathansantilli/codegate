import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowSelfHostedRunnerInput {
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

function normalizeRunsOn(value: unknown): string[] {
  if (typeof value === "string") {
    return [value.trim()];
  }

  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter((entry): entry is string => typeof entry === "string")
    .map((entry) => entry.trim());
}

function isSelfHostedRunner(value: unknown): boolean {
  return normalizeRunsOn(value).some((entry) => entry.toLowerCase() === "self-hosted");
}

export function detectWorkflowSelfHostedRunner(input: WorkflowSelfHostedRunnerInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  const root = asRecord(input.parsed);
  const jobsRecord = asRecord(root?.jobs);
  if (!facts || !jobsRecord) {
    return [];
  }

  const findings: Finding[] = [];

  for (const job of facts.jobs) {
    const jobRecord = jobsRecord[job.id];
    if (!isSelfHostedRunner(asRecord(jobRecord)?.["runs-on"])) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: ["self-hosted"],
      fallbackValue: "runs-on: self-hosted",
    });

    findings.push({
      rule_id: "workflow-self-hosted-runner",
      finding_id: `WORKFLOW_SELF_HOSTED_RUNNER-${input.filePath}-${job.id}`,
      severity: "MEDIUM",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${job.id}.runs-on` },
      description: "Job uses a self-hosted runner",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-732",
      confidence: "MEDIUM",
      fixable: false,
      remediation_actions: [
        "Prefer GitHub-hosted runners unless the workflow requires a hardened self-hosted trust boundary",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
