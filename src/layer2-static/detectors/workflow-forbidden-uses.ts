import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowForbiddenUsesRuleConfig {
  allow?: string[];
  deny?: string[];
}

export interface WorkflowForbiddenUsesInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  config?: WorkflowForbiddenUsesRuleConfig;
}

interface CompiledForbiddenPolicy {
  mode: "allow" | "deny";
  allow: RegExp[];
  deny: RegExp[];
}

function normalizePattern(value: string): string {
  return value.replaceAll("\\", "/").trim().toLowerCase();
}

function globToRegExp(glob: string): RegExp {
  const pattern = normalizePattern(glob);
  if (pattern.length === 0) {
    return /^$/;
  }

  let regex = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];

    if (char === "*") {
      if (pattern[index + 1] === "*") {
        regex += ".*";
        index += 1;
      } else {
        regex += "[^/]*";
      }
      continue;
    }

    if (char === "?") {
      regex += "[^/]";
      continue;
    }

    regex += char.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  }

  regex += "$";
  return new RegExp(regex);
}

function compilePatterns(patterns: readonly string[]): RegExp[] {
  return patterns.map((pattern) => globToRegExp(pattern));
}

function matchesRepositoryPattern(value: string, pattern: RegExp): boolean {
  return pattern.test(value.toLowerCase());
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

  const slug = trimmed.slice(0, atIndex).trim().replace(/\/+$/u, "").toLowerCase();
  const ref = trimmed
    .slice(atIndex + 1)
    .trim()
    .toLowerCase();
  if (slug.length === 0 || !slug.includes("/") || ref.length === 0) {
    return null;
  }

  return { slug, ref };
}

function getForbiddenPolicy(
  config: WorkflowForbiddenUsesRuleConfig | undefined,
): CompiledForbiddenPolicy | null {
  const allow = config?.allow?.filter((pattern) => pattern.trim().length > 0) ?? [];
  const deny = config?.deny?.filter((pattern) => pattern.trim().length > 0) ?? [];
  const allowPatterns = compilePatterns(allow);
  const denyPatterns = compilePatterns(deny);

  if (allow.length > 0) {
    return {
      mode: "allow",
      allow: allowPatterns,
      deny: denyPatterns,
    };
  }
  if (deny.length > 0) {
    return {
      mode: "deny",
      allow: [],
      deny: denyPatterns,
    };
  }
  return null;
}

function isForbidden(uses: string, policy: CompiledForbiddenPolicy): boolean {
  const parsed = parseRepositoryUses(uses);
  if (!parsed) {
    return false;
  }

  if (policy.deny.some((pattern) => matchesRepositoryPattern(parsed.slug, pattern))) {
    return true;
  }

  if (
    policy.mode === "allow" &&
    !policy.allow.some((pattern) => matchesRepositoryPattern(parsed.slug, pattern))
  ) {
    return true;
  }

  return false;
}

export function detectWorkflowForbiddenUses(input: WorkflowForbiddenUsesInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const policy = getForbiddenPolicy(input.config);
  if (!policy) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    const jobUses = job.uses?.trim();
    if (jobUses && isForbidden(jobUses, policy)) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [jobUses],
        fallbackValue: `uses: ${jobUses}`,
      });

      findings.push({
        rule_id: "workflow-forbidden-uses",
        finding_id: `WORKFLOW_FORBIDDEN_USES-JOB-${input.filePath}-${jobIndex}`,
        severity: "HIGH",
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.uses` },
        description:
          policy.mode === "allow"
            ? "Workflow uses repository action outside the configured allowlist"
            : "Workflow uses repository action matching the configured denylist",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-829",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          policy.mode === "allow"
            ? "Add the action to the allowlist only if it is explicitly trusted"
            : "Remove the action or move it to an allowlist-only policy if it is trusted",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    }

    job.steps.forEach((step, stepIndex) => {
      const uses = step.uses?.trim();
      if (!uses) {
        return;
      }

      if (!isForbidden(uses, policy)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [uses],
        fallbackValue: `uses: ${uses}`,
      });

      findings.push({
        rule_id: "workflow-forbidden-uses",
        finding_id: `WORKFLOW_FORBIDDEN_USES-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "CI_SUPPLY_CHAIN",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].uses` },
        description:
          policy.mode === "allow"
            ? "Workflow uses repository action outside the configured allowlist"
            : "Workflow uses repository action matching the configured denylist",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-829",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          policy.mode === "allow"
            ? "Add the action to the allowlist only if it is explicitly trusted"
            : "Remove the action or move it to an allowlist-only policy if it is trusted",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
