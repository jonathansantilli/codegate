import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowCachePoisoningInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const UNTRUSTED_TRIGGERS = new Set(["pull_request", "pull_request_target", "workflow_run"]);

function normalizeUsesSlug(value: string): string {
  const beforeRef = value.split("@")[0] ?? value;
  return beforeRef.replace(/\/+$/u, "").toLowerCase();
}

function isCacheAction(uses: string): boolean {
  return normalizeUsesSlug(uses).startsWith("actions/cache");
}

function hasRestoreKeys(stepWith: Record<string, string> | undefined): string | null {
  const restoreKeys = stepWith?.["restore-keys"]?.trim();
  return restoreKeys && restoreKeys.length > 0 ? restoreKeys : null;
}

export function detectWorkflowCachePoisoning(input: WorkflowCachePoisoningInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const hasUntrustedTrigger = facts.triggers.some((trigger) => UNTRUSTED_TRIGGERS.has(trigger));
  if (!hasUntrustedTrigger) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    job.steps.forEach((step, stepIndex) => {
      const uses = step.uses?.trim();
      if (!uses || !isCacheAction(uses)) {
        return;
      }

      const restoreKeys = hasRestoreKeys(step.with);
      if (!restoreKeys) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: ["restore-keys:", restoreKeys],
        fallbackValue: restoreKeys,
      });

      findings.push({
        rule_id: "workflow-cache-poisoning",
        finding_id: `WORKFLOW_CACHE_POISONING-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].with.restore-keys` },
        description: "Cache restore keys can enable cache poisoning on untrusted workflow triggers",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-345",
        confidence: "MEDIUM",
        fixable: false,
        remediation_actions: [
          "Remove broad restore keys or restrict cache reuse to trusted branches and jobs",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
