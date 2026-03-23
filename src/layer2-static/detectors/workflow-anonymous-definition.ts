import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowAnonymousDefinitionInput {
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

export function detectWorkflowAnonymousDefinition(
  input: WorkflowAnonymousDefinitionInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const root = asRecord(input.parsed);
  const name = typeof root?.name === "string" ? root.name.trim() : "";
  if (name.length > 0) {
    return [];
  }

  const evidence = buildFindingEvidence({
    textContent: input.textContent,
    searchTerms: ["name:"],
    fallbackValue: "workflow has no top-level name",
  });

  return [
    {
      rule_id: "workflow-anonymous-definition",
      finding_id: `WORKFLOW_ANONYMOUS_DEFINITION-${input.filePath}`,
      severity: "LOW",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { field: "name" },
      description:
        "Workflow omits a top-level name, reducing review clarity and incident traceability",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-200",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: ["Add an explicit top-level workflow name"],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    },
  ];
}
