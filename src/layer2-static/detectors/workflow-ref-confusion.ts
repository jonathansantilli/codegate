import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowRefConfusionInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const HASH_PINNED_REF_RE = /^[a-f0-9]{40}$/iu;

function parseRepositoryUses(value: string): { slug: string; ref: string } | null {
  const trimmed = value.trim();
  if (trimmed.startsWith("./") || trimmed.startsWith("docker://")) {
    return null;
  }

  const atIndex = trimmed.lastIndexOf("@");
  if (atIndex < 0) {
    return null;
  }

  const slug = trimmed.slice(0, atIndex).trim().replace(/\/+$/u, "").toLowerCase();
  const ref = trimmed.slice(atIndex + 1).trim();
  if (slug.length === 0 || !slug.includes("/") || ref.length === 0) {
    return null;
  }

  return { slug, ref };
}

function isHashPinned(ref: string): boolean {
  return HASH_PINNED_REF_RE.test(ref.trim());
}

export function detectWorkflowRefConfusion(input: WorkflowRefConfusionInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  for (const [jobIndex, job] of facts.jobs.entries()) {
    for (const [stepIndex, step] of job.steps.entries()) {
      const uses = step.uses?.trim();
      if (!uses) {
        continue;
      }

      const parsedUses = parseRepositoryUses(uses);
      if (!parsedUses || isHashPinned(parsedUses.ref)) {
        continue;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [uses],
        fallbackValue: `uses: ${uses}`,
      });

      findings.push({
        rule_id: "workflow-ref-confusion",
        finding_id: `WORKFLOW_REF_CONFUSION-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_VULNERABLE_ACTION",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].uses` },
        description:
          "Workflow action is pinned to a symbolic ref instead of an immutable commit hash",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-829",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: ["Pin external actions to a full commit SHA"],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    }
  }

  return findings;
}
