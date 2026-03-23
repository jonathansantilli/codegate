import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface DependabotAutoMergeInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const MERGE_COMMAND_PATTERN =
  /\b(gh\s+pr\s+merge|gh\s+pr\s+review|gh\s+api\s+[^#\n]*\/pulls\/[^#\n]*\/merge)\b/iu;

const MERGE_ACTIONS = new Set([
  "ahmadnassri/action-dependabot-auto-merge",
  "hmarr/auto-approve-action",
  "fastify/github-action-merge-dependabot",
  "ad-m/github-push-action",
  "peter-evans/create-pull-request",
]);

function normalizeUses(value: string | undefined): string | null {
  if (!value) {
    return null;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized.length === 0) {
    return null;
  }
  const atIndex = normalized.indexOf("@");
  return atIndex === -1 ? normalized : normalized.slice(0, atIndex);
}

function hasDependabotActorConstraint(condition: string | undefined): boolean {
  if (!condition) {
    return false;
  }
  const normalized = condition.toLowerCase();
  return (
    normalized.includes("dependabot[bot]") ||
    normalized.includes("dependabot-preview[bot]") ||
    normalized.includes("github.actor") ||
    normalized.includes("github.triggering_actor")
  );
}

function hasStrictRepoBoundary(condition: string | undefined): boolean {
  if (!condition) {
    return false;
  }
  const normalized = condition.toLowerCase();
  return (
    normalized.includes("github.repository == github.event.pull_request.head.repo.full_name") ||
    normalized.includes("github.event.pull_request.head.repo.fork == false") ||
    normalized.includes("github.event.pull_request.user.login") ||
    normalized.includes("github.ref == 'refs/heads/main'") ||
    normalized.includes("github.base_ref == 'main'")
  );
}

function isRiskyTrigger(trigger: string): boolean {
  const normalized = trigger.trim().toLowerCase();
  return normalized === "pull_request_target" || normalized === "workflow_run";
}

export function detectDependabotAutoMerge(input: DependabotAutoMergeInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const riskyTrigger = facts.triggers.find((trigger) => isRiskyTrigger(trigger));
  if (!riskyTrigger) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    job.steps.forEach((step, stepIndex) => {
      const mergesByCommand = Boolean(step.run && MERGE_COMMAND_PATTERN.test(step.run));
      const mergesByAction = (() => {
        const normalizedUses = normalizeUses(step.uses);
        return normalizedUses ? MERGE_ACTIONS.has(normalizedUses) : false;
      })();
      if (!mergesByCommand && !mergesByAction) {
        return;
      }

      const mergedCondition = step.if ?? job.if;
      if (!hasDependabotActorConstraint(mergedCondition)) {
        return;
      }
      if (hasStrictRepoBoundary(mergedCondition)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [
          "pull_request_target",
          "dependabot[bot]",
          "gh pr merge",
          step.uses ?? "",
          step.run ?? "",
        ],
        fallbackValue: `${job.id} auto-merge flow uses weak bot-only gating`,
      });

      findings.push({
        rule_id: "dependabot-auto-merge",
        finding_id: `DEPENDABOT_AUTO_MERGE-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: riskyTrigger === "pull_request_target" ? "HIGH" : "MEDIUM",
        category: "CI_TRIGGER",
        layer: "L2",
        file_path: input.filePath,
        location: {
          field: step.run
            ? `jobs.${job.id}.steps[${stepIndex}].run`
            : `jobs.${job.id}.steps[${stepIndex}].uses`,
        },
        description:
          "Dependabot auto-merge flow relies on weak actor-only conditions in a privileged trigger context",
        affected_tools: ["github-actions", "dependabot"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-285",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Require strict repository boundary checks before executing auto-merge operations",
          "Avoid pull_request_target auto-merge flows unless actor, repo, and branch checks are explicit",
          "Prefer dedicated Dependabot metadata and permission-check actions before merge approval",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
