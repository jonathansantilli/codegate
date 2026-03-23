import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowObfuscationInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const OBFUSCATION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /\bbase64\s+-d\b/iu,
    description: "runtime decoding of base64-encoded payload data",
  },
  {
    pattern: /\bbase64\s+-d\b[\s\S]*\|\s*(?:bash|sh)\b/iu,
    description: "base64-decoded payload piped into a shell",
  },
  {
    pattern: /\beval\b[\s\S]*\$\([^)]+base64[^)]*\)/iu,
    description: "eval executes command substitution that decodes base64 content",
  },
  {
    pattern: /\bprintf\b[\s\S]*\\x[0-9a-f]{2}/iu,
    description: "hex-encoded shell payload reconstruction",
  },
];

function detectObfuscation(run: string | undefined): { run: string; description: string } | null {
  if (!run) {
    return null;
  }
  for (const entry of OBFUSCATION_PATTERNS) {
    if (entry.pattern.test(run)) {
      return {
        run,
        description: entry.description,
      };
    }
  }
  return null;
}

export function detectWorkflowObfuscation(input: WorkflowObfuscationInput): Finding[] {
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
      const match = detectObfuscation(step.run);
      if (!match) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [match.run, "base64", "eval"],
        fallbackValue: match.run,
      });

      findings.push({
        rule_id: "workflow-obfuscation",
        finding_id: `WORKFLOW_OBFUSCATION-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "HIGH",
        category: "COMMAND_EXEC",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].run` },
        description: `Workflow run step uses obfuscated command execution (${match.description})`,
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-506",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Replace obfuscated command pipelines with explicit, reviewable commands and integrity checks",
        ],
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
