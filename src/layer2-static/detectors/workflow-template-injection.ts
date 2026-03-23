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
  "workflow_run",
]);

function hasTemplateExpression(value: string | undefined): boolean {
  return typeof value === "string" && value.includes("${{");
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
      if (hasTemplateExpression(step.run)) {
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
      if (!sinkFields || sinkFields.length === 0) {
        return;
      }

      for (const sinkField of sinkFields) {
        const sinkValue = step.with[sinkField];
        if (!hasTemplateExpression(sinkValue)) {
          continue;
        }

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
    });
  });

  return findings;
}
