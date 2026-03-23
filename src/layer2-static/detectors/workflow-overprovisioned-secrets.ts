import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowOverprovisionedSecretsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const FULL_SECRETS_SERIALIZATION = /\btojson\s*\(\s*secrets\s*\)/iu;

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

function findSerializedSecrets(
  value: unknown,
  path: string,
): { path: string; value: string } | null {
  if (typeof value === "string") {
    return FULL_SECRETS_SERIALIZATION.test(value) ? { path, value } : null;
  }

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = findSerializedSecrets(value[index], appendPath(path, index));
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
    const found = findSerializedSecrets(child, appendPath(path, key));
    if (found) {
      return found;
    }
  }

  return null;
}

export function detectWorkflowOverprovisionedSecrets(
  input: WorkflowOverprovisionedSecretsInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const found = findSerializedSecrets(input.parsed, "");
  if (!found) {
    return [];
  }

  const evidence = buildFindingEvidence({
    textContent: input.textContent,
    searchTerms: [found.value, "toJSON(secrets)", "toJson(secrets)"],
    fallbackValue: found.value,
  });

  return [
    {
      rule_id: "workflow-overprovisioned-secrets",
      finding_id: `WORKFLOW_OVERPROVISIONED_SECRETS-${input.filePath}`,
      severity: "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: found.path },
      description: "Workflow serializes the entire secrets context",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-200",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Reference only the specific secrets each step needs instead of serializing the full secrets context",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    },
  ];
}
