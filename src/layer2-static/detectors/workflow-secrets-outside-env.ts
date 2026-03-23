import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowSecretsOutsideEnvInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const DIRECT_SECRET_REFERENCE = /\bsecrets\.(?!GITHUB_TOKEN\b)[A-Za-z0-9_]+\b/iu;
const BRACKET_SECRET_REFERENCE = /\bsecrets\s*\[\s*['"][^'"\r\n]+['"]\s*\]/iu;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function appendPath(base: string, segment: string | number): string {
  if (typeof segment === "number") {
    return `${base}[${segment}]`;
  }
  return base.length > 0 ? `${base}.${segment}` : segment;
}

function findSecretReference(value: unknown, path: string): { path: string; value: string } | null {
  if (typeof value === "string") {
    return DIRECT_SECRET_REFERENCE.test(value) || BRACKET_SECRET_REFERENCE.test(value)
      ? { path, value }
      : null;
  }

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = findSecretReference(value[index], appendPath(path, index));
      if (found) {
        return found;
      }
    }
    return null;
  }

  const record = asRecord(value);
  if (!record) {
    return null;
  }

  for (const [key, child] of Object.entries(record)) {
    const found = findSecretReference(child, appendPath(path, key));
    if (found) {
      return found;
    }
  }

  return null;
}

function hasDedicatedEnvironment(job: Record<string, unknown>): boolean {
  const environment = job.environment;
  if (typeof environment === "string") {
    return environment.trim().length > 0;
  }

  return environment !== undefined && environment !== null;
}

export function detectWorkflowSecretsOutsideEnv(input: WorkflowSecretsOutsideEnvInput): Finding[] {
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
    if (!jobRecord || hasDedicatedEnvironment(jobRecord)) {
      continue;
    }

    const found = findSecretReference(jobRecord, `jobs.${job.id}`);
    if (!found) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [found.value, "secrets."],
      fallbackValue: found.value,
    });

    findings.push({
      rule_id: "workflow-secrets-outside-env",
      finding_id: `WORKFLOW_SECRETS_OUTSIDE_ENV-${input.filePath}-${job.id}`,
      severity: "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: found.path },
      description: "Job references workflow secrets without a dedicated environment",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-522",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Use a dedicated environment for secrets-bound jobs or reduce the scope of secret exposure",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
