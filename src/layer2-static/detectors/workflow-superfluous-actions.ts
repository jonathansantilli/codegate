import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowSuperfluousActionsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function normalizeUses(value: string): string {
  return value.trim().toLowerCase();
}

function isExternalUses(value: string): boolean {
  const normalized = value.trim();
  return (
    normalized.length > 0 &&
    !normalized.startsWith("./") &&
    !normalized.startsWith("../") &&
    !normalized.startsWith("docker://")
  );
}

export function detectWorkflowSuperfluousActions(
  input: WorkflowSuperfluousActionsInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    const usesCounts = new Map<string, { count: number; firstStep: number; rawUses: string }>();

    job.steps.forEach((step, stepIndex) => {
      const uses = step.uses?.trim();
      if (!uses || !isExternalUses(uses)) {
        return;
      }

      const key = normalizeUses(uses);
      const current = usesCounts.get(key);
      if (!current) {
        usesCounts.set(key, { count: 1, firstStep: stepIndex, rawUses: uses });
        return;
      }
      current.count += 1;
    });

    for (const [key, value] of usesCounts.entries()) {
      if (value.count < 2) {
        continue;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [value.rawUses],
        fallbackValue: `${value.rawUses} repeated ${value.count} times`,
      });

      findings.push({
        rule_id: "workflow-superfluous-actions",
        finding_id: `WORKFLOW_SUPERFLUOUS_ACTIONS-${input.filePath}-${jobIndex}-${key}`,
        severity: "LOW",
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${value.firstStep}].uses` },
        description: "Workflow repeats the same external action in a single job",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-1059",
        confidence: "MEDIUM",
        fixable: false,
        remediation_actions: [
          "Remove duplicate external action invocations unless repetition is explicitly required",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    }
  });

  return findings;
}
