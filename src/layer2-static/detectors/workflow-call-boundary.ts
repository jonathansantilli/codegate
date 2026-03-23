import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { extractWorkflowCallBoundaryContext } from "../workflow/analysis.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowCallBoundaryInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function collectExpressionKeys(textContent: string, prefix: "inputs" | "secrets"): Set<string> {
  const keys = new Set<string>();
  const pattern = new RegExp(`${prefix}\\.([a-zA-Z0-9_-]+)`, "giu");

  for (const match of textContent.matchAll(pattern)) {
    const key = match[1]?.trim();
    if (!key) {
      continue;
    }
    keys.add(key);
  }

  return keys;
}

export function detectWorkflowCallBoundary(input: WorkflowCallBoundaryInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const boundary = extractWorkflowCallBoundaryContext(input.parsed, facts);
  if (!boundary.hasWorkflowCall) {
    return [];
  }

  const declaredInputs = new Set(boundary.declaredInputKeys);
  const declaredSecrets = new Set(boundary.declaredSecretKeys);
  const referencedInputs = collectExpressionKeys(input.textContent, "inputs");
  const referencedSecrets = collectExpressionKeys(input.textContent, "secrets");

  const undeclaredInputs = Array.from(referencedInputs).filter((key) => !declaredInputs.has(key));
  const undeclaredSecrets = Array.from(referencedSecrets).filter(
    (key) => !declaredSecrets.has(key),
  );

  const findings: Finding[] = [];
  for (const inputKey of undeclaredInputs) {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [`inputs.${inputKey}`, "workflow_call"],
      fallbackValue: `workflow_call references undeclared input ${inputKey}`,
    });
    findings.push({
      rule_id: "workflow-call-boundary",
      finding_id: `WORKFLOW_CALL_BOUNDARY-INPUT-${input.filePath}-${inputKey}`,
      severity: "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: "on.workflow_call.inputs" },
      description: `workflow_call references undeclared input '${inputKey}'`,
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-20",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        `Declare input '${inputKey}' under on.workflow_call.inputs with explicit type and required policy`,
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  for (const secretKey of undeclaredSecrets) {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [`secrets.${secretKey}`, "workflow_call"],
      fallbackValue: `workflow_call references undeclared secret ${secretKey}`,
    });
    findings.push({
      rule_id: "workflow-call-boundary",
      finding_id: `WORKFLOW_CALL_BOUNDARY-SECRET-${input.filePath}-${secretKey}`,
      severity: "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: "on.workflow_call.secrets" },
      description: `workflow_call references undeclared secret '${secretKey}'`,
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-862",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        `Declare secret '${secretKey}' under on.workflow_call.secrets and pass only required values from callers`,
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
