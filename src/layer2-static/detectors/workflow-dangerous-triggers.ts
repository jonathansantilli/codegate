import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

const DANGEROUS_TRIGGERS = new Set(["pull_request_target", "workflow_run"]);

export interface WorkflowDangerousTriggersInput {
  filePath: string;
  parsed: unknown;
}

export function detectWorkflowDangerousTriggers(input: WorkflowDangerousTriggersInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const triggers = facts.triggers.filter((trigger) => DANGEROUS_TRIGGERS.has(trigger));
  if (triggers.length === 0) {
    return [];
  }

  return [
    {
      rule_id: "workflow-dangerous-triggers",
      finding_id: `WORKFLOW_DANGEROUS_TRIGGERS-${input.filePath}`,
      severity: "HIGH",
      category: "CI_TRIGGER",
      layer: "L2",
      file_path: input.filePath,
      location: { field: "on" },
      description: `Workflow uses high-risk trigger(s): ${triggers.join(", ")}`,
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-693",
      confidence: "MEDIUM",
      fixable: false,
      remediation_actions: [
        "Restrict trigger conditions and avoid running untrusted pull request data in privileged contexts",
      ],
      evidence: triggers.join(", "),
      suppressed: false,
    },
  ];
}
