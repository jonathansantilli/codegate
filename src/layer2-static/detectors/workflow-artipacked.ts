import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowArtipackedInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function isCheckoutStep(uses: string | undefined): boolean {
  return typeof uses === "string" && /^actions\/checkout(?:@.+)?$/iu.test(uses.trim());
}

function persistsCredentials(value: unknown): boolean {
  if (typeof value !== "string") {
    return true;
  }

  return value.trim().toLowerCase() !== "false";
}

export function detectWorkflowArtipacked(input: WorkflowArtipackedInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    job.steps.forEach((step, stepIndex) => {
      if (!isCheckoutStep(step.uses)) {
        return;
      }

      if (!persistsCredentials(step.with?.["persist-credentials"])) {
        return;
      }

      const searchTerms = ["persist-credentials: true"];
      if (step.uses) {
        searchTerms.push(step.uses);
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms,
        fallbackValue: "actions/checkout persists credentials on disk",
      });

      findings.push({
        rule_id: "workflow-artipacked",
        finding_id: `WORKFLOW_ARTIPACKED-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].with.persist-credentials` },
        description: "Checkout step persists credentials on disk",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-922",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Set actions/checkout persist-credentials to false unless the workflow explicitly needs Git credentials",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
