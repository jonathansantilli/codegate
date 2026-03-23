import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowInsecureCommandsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const INSECURE_COMMAND_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /\b(?:curl|wget)\b[\s\S]*?\|\s*(?:sh|bash)\b/iu,
    description: "remote download piped directly into a shell",
  },
  {
    pattern: /\bbash\s*<\s*\(\s*curl\b/iu,
    description: "process substitution executes downloaded shell content",
  },
  {
    pattern: /\bsh\s*<\s*\(\s*curl\b/iu,
    description: "process substitution executes downloaded shell content",
  },
];

function findInsecureCommand(
  run: string | undefined,
): { match: string; description: string } | null {
  if (typeof run !== "string") {
    return null;
  }

  for (const entry of INSECURE_COMMAND_PATTERNS) {
    if (entry.pattern.test(run)) {
      return { match: run, description: entry.description };
    }
  }

  return null;
}

export function detectWorkflowInsecureCommands(input: WorkflowInsecureCommandsInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    job.steps.forEach((step, stepIndex) => {
      const insecure = findInsecureCommand(step.run);
      if (!insecure) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [insecure.match],
        fallbackValue: insecure.match,
      });

      findings.push({
        rule_id: "workflow-insecure-commands",
        finding_id: `WORKFLOW_INSECURE_COMMANDS-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "COMMAND_EXEC",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].run` },
        description: `Workflow uses ${insecure.description}`,
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-78",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Download artifacts separately, verify integrity, and run them only after review",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
