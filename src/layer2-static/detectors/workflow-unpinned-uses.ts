import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowUnpinnedUsesInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function isPinnedToCommit(ref: string): boolean {
  return /^[a-f0-9]{40}$/iu.test(ref.trim());
}

function isRepositoryUses(value: string): boolean {
  return /^[a-z0-9._-]+\/[a-z0-9._-]+(?:\/[^@]+)?@[^\s]+$/iu.test(value.trim());
}

export function detectWorkflowUnpinnedUses(input: WorkflowUnpinnedUsesInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    const jobUses = job.uses?.trim();
    if (jobUses && !jobUses.startsWith("./") && !jobUses.startsWith("docker://")) {
      if (isRepositoryUses(jobUses)) {
        const ref = jobUses.split("@").slice(1).join("@").trim();
        if (ref.length > 0 && !isPinnedToCommit(ref)) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            searchTerms: [jobUses],
            fallbackValue: `uses: ${jobUses}`,
          });

          findings.push({
            rule_id: "workflow-unpinned-uses",
            finding_id: `WORKFLOW_UNPINNED_USES-JOB-${input.filePath}-${jobIndex}`,
            severity: "HIGH",
            category: "CI_SUPPLY_CHAIN",
            layer: "L2",
            file_path: input.filePath,
            location: { field: `jobs.${job.id}.uses` },
            description: "Workflow reusable reference is not pinned to an immutable commit hash",
            affected_tools: ["github-actions"],
            cve: null,
            owasp: ["ASI02"],
            cwe: "CWE-829",
            confidence: "HIGH",
            fixable: false,
            remediation_actions: [
              "Pin reusable workflows to a full commit SHA and track tag intent in comments",
            ],
            evidence: evidence?.evidence ?? null,
            suppressed: false,
          });
        }
      }
    }

    job.steps.forEach((step, stepIndex) => {
      const uses = step.uses?.trim();
      if (!uses || uses.startsWith("./") || uses.startsWith("docker://")) {
        return;
      }
      if (!isRepositoryUses(uses)) {
        return;
      }

      const ref = uses.split("@").slice(1).join("@").trim();
      if (ref.length === 0 || isPinnedToCommit(ref)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [uses],
        fallbackValue: `uses: ${uses}`,
      });

      findings.push({
        rule_id: "workflow-unpinned-uses",
        finding_id: `WORKFLOW_UNPINNED_USES-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].uses` },
        description: "Workflow action reference is not pinned to an immutable commit hash",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-829",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Pin external actions to a full commit SHA and track tag intent in comments",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
