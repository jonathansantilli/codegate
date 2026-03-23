import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { isGitHubDependabotPath } from "../dependabot/parser.js";

export interface DependabotExecutionInput {
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

function isExternalCodeExecutionAllowed(value: unknown): boolean {
  if (value === true) {
    return true;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return normalized === "allow" || normalized === "true";
  }
  return false;
}

export function detectDependabotExecution(input: DependabotExecutionInput): Finding[] {
  if (!isGitHubDependabotPath(input.filePath)) {
    return [];
  }

  const root = asRecord(input.parsed);
  const updates = Array.isArray(root?.updates) ? root.updates : [];
  if (updates.length === 0) {
    return [];
  }

  const findings: Finding[] = [];

  updates.forEach((entry, index) => {
    const update = asRecord(entry);
    if (!update) {
      return;
    }

    if (!isExternalCodeExecutionAllowed(update["insecure-external-code-execution"])) {
      return;
    }

    const ecosystem =
      typeof update["package-ecosystem"] === "string"
        ? update["package-ecosystem"]
        : "unknown-ecosystem";
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [ecosystem, "insecure-external-code-execution", "allow"],
      fallbackValue: `${ecosystem} enables insecure external code execution`,
    });

    findings.push({
      rule_id: "dependabot-execution",
      finding_id: `DEPENDABOT_EXECUTION-${input.filePath}-${index}`,
      severity: "HIGH",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `updates[${index}].insecure-external-code-execution` },
      description: "Dependabot update rule allows insecure external code execution",
      affected_tools: ["dependabot"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-94",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Remove insecure-external-code-execution allowances and isolate registries through trusted credentials",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  });

  return findings;
}
