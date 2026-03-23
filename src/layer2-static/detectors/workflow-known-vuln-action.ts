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

function parseSemverLike(value: string): [number, number, number] | null {
  const match = value.trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$/iu);
  if (!match?.[1]) {
    return null;
  }

  return [
    Number.parseInt(match[1], 10),
    Number.parseInt(match[2] ?? "0", 10),
    Number.parseInt(match[3] ?? "0", 10),
  ];
}

function compareSemverLike(
  left: [number, number, number],
  right: [number, number, number],
): number {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] < right[index]) {
      return -1;
    }
    if (left[index] > right[index]) {
      return 1;
    }
  }
  return 0;
}

function matchesComparator(ref: string, comparator: string): boolean {
  const match = comparator.trim().match(/^(<=|>=|<|>|=)\s*(v?\d+(?:\.\d+){0,2})$/iu);
  if (!match?.[1] || !match[2]) {
    return false;
  }

  const refVersion = parseSemverLike(ref);
  const comparatorVersion = parseSemverLike(match[2]);
  if (!refVersion || !comparatorVersion) {
    return false;
  }

  const comparison = compareSemverLike(refVersion, comparatorVersion);
  switch (match[1]) {
    case "<":
      return comparison < 0;
    case "<=":
      return comparison <= 0;
    case ">":
      return comparison > 0;
    case ">=":
      return comparison >= 0;
    case "=":
      return comparison === 0;
    default:
      return false;
  }
}

function matchesVulnerablePattern(ref: string, pattern: string): boolean {
  const normalizedRef = ref.trim().toLowerCase();
  const normalizedPattern = pattern.trim().toLowerCase();
  if (normalizedPattern.length === 0) {
    return false;
  }

  if (normalizedPattern.includes("*")) {
    return normalizedPattern.endsWith("*")
      ? normalizedRef.startsWith(normalizedPattern.slice(0, -1))
      : normalizedRef === normalizedPattern;
  }

  if (/^(?:<=|>=|<|>|=)/u.test(normalizedPattern)) {
    const comparators = normalizedPattern.split(/\s+/u).filter((token) => token.length > 0);
    return comparators.every((comparator) => matchesComparator(normalizedRef, comparator));
  }

  return normalizedRef === normalizedPattern;
}

function isKnownVulnerableRef(ref: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesVulnerablePattern(ref, pattern));
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
    const jobUses = job.uses;
    if (jobUses) {
      const parsedJobUses = parseRepositoryUses(jobUses);
      if (parsedJobUses) {
        const vulnerableVersions = advisories[parsedJobUses.slug];
        if (vulnerableVersions && isKnownVulnerableRef(parsedJobUses.ref, vulnerableVersions)) {
          findings.push({
            rule_id: "workflow-known-vuln-action",
            finding_id: `WORKFLOW_KNOWN_VULN_ACTION-JOB-${input.filePath}-${jobIndex}`,
            severity: "HIGH",
            category: "CI_VULNERABLE_ACTION",
            layer: "L2",
            file_path: input.filePath,
            location: { field: `jobs.${job.id}.uses` },
            description: `Action ${parsedJobUses.slug}@${parsedJobUses.ref} is listed in known vulnerable references`,
            affected_tools: ["github-actions"],
            cve: null,
            owasp: ["ASI02"],
            cwe: "CWE-937",
            confidence: "HIGH",
            fixable: false,
            remediation_actions: [
              "Upgrade to a non-vulnerable action release and pin to a reviewed commit SHA",
            ],
            evidence: jobUses,
            suppressed: false,
          });
        }
      }
    }

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
      if (!vulnerableVersions || !isKnownVulnerableRef(parsedUses.ref, vulnerableVersions)) {
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
