import sinkMap from "../workflow/injection-sinks.json" with { type: "json" };
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowTemplateInjectionInput {
  filePath: string;
  parsed: unknown;
}

const UNTRUSTED_TRIGGERS = new Set([
  "pull_request",
  "pull_request_target",
  "issue_comment",
  "discussion_comment",
  "pull_request_review_comment",
  "workflow_run",
]);

function hasTemplateExpression(value: string | undefined): boolean {
  return typeof value === "string" && value.includes("${{");
}

const UNTRUSTED_EVENT_REFERENCE_PATTERNS = [
  /\bgithub\.event\.pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.full_name)\b/iu,
  /\bgithub\.event\.issue\.(?:title|body)\b/iu,
  /\bgithub\.event\.comment\.body\b/iu,
  /\bgithub\.event\.review\.body\b/iu,
  /\bgithub\.event\.discussion\.body\b/iu,
  /\bgithub\.head_ref\b/iu,
];

const PRIVILEGED_COMMAND_PATTERNS = [
  /\bgh\s+release\b/iu,
  /\bdeploy\b/iu,
  /\bpublish\b/iu,
  /\brelease\b/iu,
  /\bcurl\b/iu,
  /\bwget\b/iu,
  /\bbash\b/iu,
  /\bsh\b/iu,
];

function hasUntrustedEventReference(value: string | undefined): boolean {
  if (typeof value !== "string") {
    return false;
  }

  return UNTRUSTED_EVENT_REFERENCE_PATTERNS.some((pattern) => pattern.test(value));
}

function hasUntrustedTemplateExpression(value: string | undefined): boolean {
  return hasTemplateExpression(value) && hasUntrustedEventReference(value);
}

function isPrivilegedStep(run: string | undefined, uses: string | undefined): boolean {
  if (typeof uses === "string" && uses.trim().length > 0) {
    return true;
  }
  if (typeof run !== "string") {
    return false;
  }
  return PRIVILEGED_COMMAND_PATTERNS.some((pattern) => pattern.test(run));
}

function normalizeUsesSlug(value: string): string {
  const beforeRef = value.split("@")[0] ?? value;
  return beforeRef.replace(/\/+$/u, "").toLowerCase();
}

export function detectWorkflowTemplateInjection(input: WorkflowTemplateInjectionInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const hasUntrustedTrigger = facts.triggers.some((trigger) => UNTRUSTED_TRIGGERS.has(trigger));
  if (!hasUntrustedTrigger) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    job.steps.forEach((step, stepIndex) => {
      if (step.if && hasUntrustedEventReference(step.if) && isPrivilegedStep(step.run, step.uses)) {
        findings.push({
          rule_id: "workflow-template-injection",
          finding_id: `WORKFLOW_TEMPLATE_INJECTION-CONDITION-${input.filePath}-${jobIndex}-${stepIndex}`,
          severity: "HIGH",
          category: "CI_TEMPLATE_INJECTION",
          layer: "L2",
          file_path: input.filePath,
          location: { field: `jobs.${job.id}.steps[${stepIndex}].if` },
          description:
            "Step condition trusts attacker-controlled issue, comment, or pull request content before privileged execution",
          affected_tools: ["github-actions"],
          cve: null,
          owasp: ["ASI02"],
          cwe: "CWE-20",
          confidence: "HIGH",
          fixable: false,
          remediation_actions: [
            "Do not gate privileged steps on raw issue/comment/pull-request text",
            "Require explicit allow-lists or trusted actor checks before executing privileged paths",
          ],
          evidence: step.if,
          suppressed: false,
        });
      }

      if (hasUntrustedTemplateExpression(step.run)) {
        findings.push({
          rule_id: "workflow-template-injection",
          finding_id: `WORKFLOW_TEMPLATE_INJECTION-RUN-${input.filePath}-${jobIndex}-${stepIndex}`,
          severity: "HIGH",
          category: "CI_TEMPLATE_INJECTION",
          layer: "L2",
          file_path: input.filePath,
          location: { field: `jobs.${job.id}.steps[${stepIndex}].run` },
          description:
            "Template expression in run step may allow untrusted input to reach shell execution",
          affected_tools: ["github-actions"],
          cve: null,
          owasp: ["ASI02"],
          cwe: "CWE-94",
          confidence: "HIGH",
          fixable: false,
          remediation_actions: [
            "Move untrusted template expressions into validated environment variables before execution",
          ],
          evidence: step.run ?? null,
          suppressed: false,
        });
      }

      const uses = step.uses?.trim();
      if (!uses || !step.with) {
        return;
      }
      const slug = normalizeUsesSlug(uses);
      const sinkFields = (sinkMap as Record<string, string[]>)[slug];
      const flaggedSinkFields = new Set<string>();
      if (sinkFields && sinkFields.length > 0) {
        for (const sinkField of sinkFields) {
          const sinkValue = step.with[sinkField];
          if (!hasUntrustedTemplateExpression(sinkValue)) {
            continue;
          }
          flaggedSinkFields.add(sinkField);

          findings.push({
            rule_id: "workflow-template-injection",
            finding_id: `WORKFLOW_TEMPLATE_INJECTION-SINK-${input.filePath}-${jobIndex}-${stepIndex}-${sinkField}`,
            severity: "HIGH",
            category: "CI_TEMPLATE_INJECTION",
            layer: "L2",
            file_path: input.filePath,
            location: { field: `jobs.${job.id}.steps[${stepIndex}].with.${sinkField}` },
            description:
              "Template expression reaches an action input known to execute code or evaluate scripts",
            affected_tools: ["github-actions"],
            cve: null,
            owasp: ["ASI02"],
            cwe: "CWE-94",
            confidence: "HIGH",
            fixable: false,
            remediation_actions: [
              "Avoid passing untrusted template expressions into code execution sink inputs",
            ],
            evidence: sinkValue,
            suppressed: false,
          });
        }
      }

      for (const [inputField, inputValue] of Object.entries(step.with)) {
        if (flaggedSinkFields.has(inputField) || !hasUntrustedTemplateExpression(inputValue)) {
          continue;
        }

        findings.push({
          rule_id: "workflow-template-injection",
          finding_id: `WORKFLOW_TEMPLATE_INJECTION-WITH-${input.filePath}-${jobIndex}-${stepIndex}-${inputField}`,
          severity: "MEDIUM",
          category: "CI_TEMPLATE_INJECTION",
          layer: "L2",
          file_path: input.filePath,
          location: { field: `jobs.${job.id}.steps[${stepIndex}].with.${inputField}` },
          description:
            "Action input receives attacker-controlled issue, comment, or pull request content",
          affected_tools: ["github-actions"],
          cve: null,
          owasp: ["ASI02"],
          cwe: "CWE-20",
          confidence: "HIGH",
          fixable: false,
          remediation_actions: [
            "Do not pass raw issue/comment/pull-request text into action inputs without validation",
            "Prefer explicit allow-lists and strict parsing for any user-controlled values",
          ],
          evidence: inputValue,
          suppressed: false,
        });
      }
    });
  });

  return findings;
}
