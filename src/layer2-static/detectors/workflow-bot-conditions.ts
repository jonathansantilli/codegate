import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowBotConditionsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface ConditionalStep {
  jobId: string;
  stepIndex?: number;
  condition: string;
  locationField: string;
  run?: string;
  uses?: string;
}

const BOT_CONDITION_PATTERN =
  /github\.actor\s*(?:==|!=)\s*['"](?:dependabot\[bot\]|renovate\[bot\]|github-actions\[bot\])['"]/iu;
const PRIVILEGED_RUN_TOKENS = ["publish", "deploy", "release", "npm publish", "gh release"];

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function gatherConditionalSteps(parsed: unknown): ConditionalStep[] {
  const root = asRecord(parsed);
  const jobs = asRecord(root?.jobs);
  if (!jobs) {
    return [];
  }

  const steps: ConditionalStep[] = [];
  for (const [jobId, jobValue] of Object.entries(jobs)) {
    const job = asRecord(jobValue);
    const stepEntries = Array.isArray(job?.steps) ? job.steps : [];
    const jobCondition = typeof job?.if === "string" ? job.if : undefined;

    if (jobCondition) {
      const hasPrivilegedStep = stepEntries.some((stepValue) => {
        const step = asRecord(stepValue);
        const run = typeof step?.run === "string" ? step.run : undefined;
        const uses = typeof step?.uses === "string" ? step.uses : undefined;
        return isPrivilegedStep(run, uses);
      });

      if (hasPrivilegedStep) {
        steps.push({
          jobId,
          condition: jobCondition,
          locationField: `jobs.${jobId}.if`,
          run: stepEntries
            .map((stepValue) => asRecord(stepValue))
            .find((step) => step && typeof step.run === "string")?.run as string | undefined,
          uses: stepEntries
            .map((stepValue) => asRecord(stepValue))
            .find((step) => step && typeof step.uses === "string")?.uses as string | undefined,
        });
      }
    }

    stepEntries.forEach((stepValue, stepIndex) => {
      const step = asRecord(stepValue);
      if (!step || typeof step.if !== "string") {
        return;
      }

      steps.push({
        jobId,
        stepIndex,
        condition: step.if,
        locationField: `jobs.${jobId}.steps[${stepIndex}].if`,
        run: typeof step.run === "string" ? step.run : undefined,
        uses: typeof step.uses === "string" ? step.uses : undefined,
      });
    });
  }

  return steps;
}

function isPrivilegedStep(run: string | undefined, uses: string | undefined): boolean {
  const runValue = run?.toLowerCase() ?? "";
  if (PRIVILEGED_RUN_TOKENS.some((token) => runValue.includes(token))) {
    return true;
  }
  return typeof uses === "string" && uses.trim().length > 0;
}

export function detectWorkflowBotConditions(input: WorkflowBotConditionsInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];
  for (const step of gatherConditionalSteps(input.parsed)) {
    if (!BOT_CONDITION_PATTERN.test(step.condition) || !isPrivilegedStep(step.run, step.uses)) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [step.condition, step.run ?? "", step.uses ?? ""],
      fallbackValue: step.condition,
    });

    findings.push({
      rule_id: "bot-conditions",
      finding_id: `BOT_CONDITIONS-${input.filePath}-${step.locationField}`,
      severity: "MEDIUM",
      category: "CI_TRIGGER",
      layer: "L2",
      file_path: input.filePath,
      location: { field: step.locationField },
      description: "Privileged workflow step is guarded primarily by bot-actor identity checks",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-287",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Use explicit trust-boundary checks (event type, branch protection, ref, permissions) beyond actor-name conditions",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
