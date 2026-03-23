import type { RuntimeMode } from "../../config.js";
import type { Finding } from "../../types/finding.js";
import { loadKnownVulnerableActions } from "../advisories/gha-advisory-client.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowKnownVulnActionInput {
  filePath: string;
  parsed: unknown;
  runtimeMode?: RuntimeMode;
}

function parseRepositoryUses(value: string): { slug: string; ref: string } | null {
  const trimmed = value.trim();
  if (trimmed.startsWith("./") || trimmed.startsWith("docker://")) {
    return null;
  }

  const atIndex = trimmed.lastIndexOf("@");
  if (atIndex < 0) {
    return null;
  }

  const slug = trimmed.slice(0, atIndex).toLowerCase();
  const ref = trimmed.slice(atIndex + 1).toLowerCase();
  if (!slug.includes("/") || ref.length === 0) {
    return null;
  }

  return { slug, ref };
}

export function detectWorkflowKnownVulnAction(input: WorkflowKnownVulnActionInput): Finding[] {
  if (input.runtimeMode !== "online") {
    return [];
  }
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const advisories = loadKnownVulnerableActions({ runtimeMode: input.runtimeMode }).advisories;
  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    job.steps.forEach((step, stepIndex) => {
      const uses = step.uses;
      if (!uses) {
        return;
      }
      const parsedUses = parseRepositoryUses(uses);
      if (!parsedUses) {
        return;
      }

      const vulnerableVersions = advisories[parsedUses.slug];
      if (!vulnerableVersions || !vulnerableVersions.includes(parsedUses.ref)) {
        return;
      }

      findings.push({
        rule_id: "workflow-known-vuln-action",
        finding_id: `WORKFLOW_KNOWN_VULN_ACTION-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_VULNERABLE_ACTION",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].uses` },
        description: `Action ${parsedUses.slug}@${parsedUses.ref} is listed in known vulnerable references`,
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-937",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Upgrade to a non-vulnerable action release and pin to a reviewed commit SHA",
        ],
        evidence: uses,
        suppressed: false,
      });
    });
  });

  return findings;
}
