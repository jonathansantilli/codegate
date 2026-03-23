import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowUseTrustedPublishingInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const PUBLISH_COMMANDS = ["npm publish", "pnpm publish", "yarn npm publish", "twine upload"];
const TOKEN_NAMES = ["NODE_AUTH_TOKEN", "NPM_TOKEN", "TWINE_USERNAME", "TWINE_PASSWORD"];

function containsPublishCommand(value: string | undefined): boolean {
  if (!value) {
    return false;
  }
  return PUBLISH_COMMANDS.some((command) => value.includes(command));
}

function findTokenName(textContent: string): string | null {
  for (const tokenName of TOKEN_NAMES) {
    if (textContent.includes(tokenName)) {
      return tokenName;
    }
  }
  return null;
}

export function detectWorkflowUseTrustedPublishing(
  input: WorkflowUseTrustedPublishingInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const tokenName = findTokenName(input.textContent);
  if (!tokenName) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    job.steps.forEach((step, stepIndex) => {
      if (!containsPublishCommand(step.run)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [step.run ?? "", tokenName],
        fallbackValue: step.run ?? tokenName,
      });

      findings.push({
        rule_id: "workflow-use-trusted-publishing",
        finding_id: `WORKFLOW_USE_TRUSTED_PUBLISHING-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_PERMISSIONS",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].run` },
        description:
          "Package publication uses long-lived registry credentials instead of trusted publishing",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-798",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Switch package publishing to trusted publishing with OIDC and remove registry secrets",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
