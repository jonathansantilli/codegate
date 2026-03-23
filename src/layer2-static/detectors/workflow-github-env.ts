import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowGithubEnvInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function writesToGithubEnv(run: string | undefined): boolean {
  return typeof run === "string" && />>\s*["']?\$?\{?GITHUB_ENV\}?/iu.test(run);
}

export function detectWorkflowGithubEnv(input: WorkflowGithubEnvInput): Finding[] {
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
      if (!writesToGithubEnv(step.run)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [step.run ?? "", "GITHUB_ENV"],
        fallbackValue: step.run ?? "write to GITHUB_ENV",
      });

      findings.push({
        rule_id: "workflow-github-env",
        finding_id: `WORKFLOW_GITHUB_ENV-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].run` },
        description: "Run step writes to GITHUB_ENV",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-94",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Avoid writing attacker-controlled values to GITHUB_ENV and prefer validated environment variables",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
