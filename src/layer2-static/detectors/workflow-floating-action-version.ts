import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowFloatingActionVersionInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const FLOATING_VERSION_VALUES = new Set(["latest", "stable", "edge", "nightly", "main", "master"]);
const VERSION_KEY_PATTERN = /version/iu;

function isRepositoryUses(value: string | undefined): boolean {
  if (typeof value !== "string") {
    return false;
  }
  return /^[a-z0-9._-]+\/[a-z0-9._-]+(?:\/[^@]+)?@[^\s]+$/iu.test(value.trim());
}

function isFloatingVersionValue(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return FLOATING_VERSION_VALUES.has(normalized);
}

export function detectWorkflowFloatingActionVersion(
  input: WorkflowFloatingActionVersionInput,
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
    job.steps.forEach((step, stepIndex) => {
      if (!isRepositoryUses(step.uses) || !step.with) {
        return;
      }

      for (const [withKey, withValue] of Object.entries(step.with)) {
        if (!VERSION_KEY_PATTERN.test(withKey) || !isFloatingVersionValue(withValue)) {
          continue;
        }

        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          searchTerms: [step.uses ?? "", withKey, withValue],
          fallbackValue: `${withKey}: ${withValue}`,
        });

        findings.push({
          rule_id: "workflow-floating-action-version",
          finding_id: `WORKFLOW_FLOATING_ACTION_VERSION-${input.filePath}-${jobIndex}-${stepIndex}-${withKey}`,
          severity: "MEDIUM",
          category: "CI_SUPPLY_CHAIN",
          layer: "L2",
          file_path: input.filePath,
          location: { field: `jobs.${job.id}.steps[${stepIndex}].with.${withKey}` },
          description:
            "Action input uses a floating version selector, which can pull unexpected releases over time",
          affected_tools: ["github-actions"],
          cve: null,
          owasp: ["ASI02"],
          cwe: "CWE-1104",
          confidence: "HIGH",
          fixable: false,
          remediation_actions: [
            "Pin action input versions to explicit releases instead of mutable selectors like latest",
          ],
          evidence: evidence?.evidence ?? null,
          suppressed: false,
        });
      }
    });
  });

  return findings;
}
