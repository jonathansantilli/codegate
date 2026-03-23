import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowGithubEnvInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface CommandFileSpec {
  name: "GITHUB_ENV" | "GITHUB_PATH" | "GITHUB_OUTPUT" | "GITHUB_STATE";
  severity: Finding["severity"];
  writePatterns: RegExp[];
}

const UNTRUSTED_TRIGGERS = new Set([
  "pull_request",
  "pull_request_target",
  "issue_comment",
  "discussion_comment",
  "pull_request_review_comment",
  "workflow_run",
]);

const UNTRUSTED_EVENT_REFERENCE_PATTERNS = [
  /\bgithub\.event\.pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.full_name)\b/iu,
  /\bgithub\.event\.issue\.(?:title|body)\b/iu,
  /\bgithub\.event\.comment\.body\b/iu,
  /\bgithub\.event\.review\.body\b/iu,
  /\bgithub\.event\.discussion\.body\b/iu,
  /\bgithub\.head_ref\b/iu,
];

const COMMAND_FILE_SPECS: CommandFileSpec[] = [
  {
    name: "GITHUB_ENV",
    severity: "HIGH",
    writePatterns: [/>>\s*["']?\$?\{?GITHUB_ENV\}?/iu, /\btee\s+-a\s+["']?\$?\{?GITHUB_ENV\}?/iu],
  },
  {
    name: "GITHUB_PATH",
    severity: "CRITICAL",
    writePatterns: [/>>\s*["']?\$?\{?GITHUB_PATH\}?/iu, /\btee\s+-a\s+["']?\$?\{?GITHUB_PATH\}?/iu],
  },
  {
    name: "GITHUB_OUTPUT",
    severity: "HIGH",
    writePatterns: [
      />>\s*["']?\$?\{?GITHUB_OUTPUT\}?/iu,
      /\btee\s+-a\s+["']?\$?\{?GITHUB_OUTPUT\}?/iu,
    ],
  },
  {
    name: "GITHUB_STATE",
    severity: "MEDIUM",
    writePatterns: [
      />>\s*["']?\$?\{?GITHUB_STATE\}?/iu,
      /\btee\s+-a\s+["']?\$?\{?GITHUB_STATE\}?/iu,
    ],
  },
];

function hasUntrustedEventReference(value: string | undefined): boolean {
  if (typeof value !== "string") {
    return false;
  }

  return UNTRUSTED_EVENT_REFERENCE_PATTERNS.some((pattern) => pattern.test(value));
}

function collectWrittenCommandFiles(run: string | undefined): CommandFileSpec[] {
  if (typeof run !== "string") {
    return [];
  }

  return COMMAND_FILE_SPECS.filter((spec) =>
    spec.writePatterns.some((pattern) => pattern.test(run)),
  );
}

export function detectWorkflowGithubEnv(input: WorkflowGithubEnvInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];
  const hasUntrustedTrigger = facts.triggers.some((trigger) => UNTRUSTED_TRIGGERS.has(trigger));

  facts.jobs.forEach((job, jobIndex) => {
    job.steps.forEach((step, stepIndex) => {
      const writtenCommandFiles = collectWrittenCommandFiles(step.run);
      if (writtenCommandFiles.length === 0) {
        return;
      }

      if (!hasUntrustedTrigger && !hasUntrustedEventReference(step.run)) {
        return;
      }

      writtenCommandFiles.forEach((commandFile) => {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          searchTerms: [step.run ?? "", commandFile.name],
          fallbackValue: step.run ?? `write to ${commandFile.name}`,
        });

        findings.push({
          rule_id: "workflow-command-file-poisoning",
          finding_id: `WORKFLOW_COMMAND_FILE_POISONING-${commandFile.name}-${input.filePath}-${jobIndex}-${stepIndex}`,
          severity: commandFile.severity,
          category: "CI_TEMPLATE_INJECTION",
          layer: "L2",
          file_path: input.filePath,
          location: { field: `jobs.${job.id}.steps[${stepIndex}].run` },
          description: `Run step writes to ${commandFile.name} in an untrusted workflow context`,
          affected_tools: ["github-actions"],
          cve: null,
          owasp: ["ASI02"],
          cwe: "CWE-94",
          confidence: "HIGH",
          fixable: false,
          remediation_actions: [
            "Avoid writing attacker-controlled values into GitHub command files",
            "Use strict allow-lists and sanitization before propagating untrusted data between workflow steps",
          ],
          evidence: evidence?.evidence ?? null,
          suppressed: false,
        });
      });
    });
  });

  return findings;
}
