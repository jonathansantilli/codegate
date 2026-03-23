import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowUnredactedSecretsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface SecretCandidate {
  field: string;
  key: string;
  value: string;
}

const SECRET_KEY_PATTERN = /(token|password|secret|api[_-]?key|private[_-]?key|access[_-]?key)/iu;
const REDACTED_VALUE_PATTERN = /^\s*\$\{\{\s*secrets\.[^}]+\}\}\s*$/iu;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function collectEnvSecrets(
  envValue: unknown,
  baseField: string,
  candidates: SecretCandidate[],
): void {
  const env = asRecord(envValue);
  if (!env) {
    return;
  }

  for (const [key, value] of Object.entries(env)) {
    if (!SECRET_KEY_PATTERN.test(key) || typeof value !== "string") {
      continue;
    }
    const trimmed = value.trim();
    if (trimmed.length < 8 || REDACTED_VALUE_PATTERN.test(trimmed)) {
      continue;
    }
    candidates.push({
      field: `${baseField}.${key}`,
      key,
      value: trimmed,
    });
  }
}

function gatherSecretCandidates(parsed: unknown): SecretCandidate[] {
  const root = asRecord(parsed);
  const candidates: SecretCandidate[] = [];

  collectEnvSecrets(root?.env, "env", candidates);

  const jobs = asRecord(root?.jobs);
  if (!jobs) {
    return candidates;
  }

  for (const [jobId, jobValue] of Object.entries(jobs)) {
    const job = asRecord(jobValue);
    if (!job) {
      continue;
    }

    collectEnvSecrets(job.env, `jobs.${jobId}.env`, candidates);

    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((stepValue, stepIndex) => {
      const step = asRecord(stepValue);
      if (!step) {
        return;
      }
      collectEnvSecrets(step.env, `jobs.${jobId}.steps[${stepIndex}].env`, candidates);
    });
  }

  return candidates;
}

export function detectWorkflowUnredactedSecrets(input: WorkflowUnredactedSecretsInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  return gatherSecretCandidates(input.parsed).map((candidate) => {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [candidate.key, candidate.value],
      fallbackValue: `${candidate.key} set to plaintext value`,
    });

    return {
      rule_id: "unredacted-secrets",
      finding_id: `UNREDACTED_SECRETS-${input.filePath}-${candidate.field}`,
      severity: "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2" as const,
      file_path: input.filePath,
      location: { field: candidate.field },
      description: "Workflow exposes a plaintext secret-like value in environment configuration",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-798",
      confidence: "HIGH" as const,
      fixable: false,
      remediation_actions: [
        "Move secret material to GitHub encrypted secrets and reference it via ${{ secrets.* }}",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    };
  });
}
