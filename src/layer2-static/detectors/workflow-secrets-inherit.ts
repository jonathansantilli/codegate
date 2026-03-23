import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowSecretsInheritInput {
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

function isReusableWorkflowCall(uses: unknown): uses is string {
  return typeof uses === "string" && uses.includes("/.github/workflows/");
}

function isInheritSecrets(value: unknown): boolean {
  return typeof value === "string" && value.trim().toLowerCase() === "inherit";
}

export function detectWorkflowSecretsInherit(input: WorkflowSecretsInheritInput): Finding[] {
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
    const jobRecord = asRecord(jobsRecord[job.id]);
    if (
      !jobRecord ||
      !isReusableWorkflowCall(jobRecord.uses) ||
      !isInheritSecrets(jobRecord.secrets)
    ) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: ["secrets: inherit", "inherit"],
      fallbackValue: "secrets: inherit",
    });

    findings.push({
      rule_id: "workflow-secrets-inherit",
      finding_id: `WORKFLOW_SECRETS_INHERIT-${input.filePath}-${job.id}`,
      severity: "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${job.id}.secrets` },
      description: "Reusable workflow call inherits all repository secrets",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-200",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: ["Pass only the specific secrets required by the reusable workflow"],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
