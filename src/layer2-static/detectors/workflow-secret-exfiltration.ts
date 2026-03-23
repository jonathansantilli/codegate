import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowSecretExfiltrationInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  trustedApiDomains: string[];
}

const OUTBOUND_COMMAND_PATTERN = /\b(curl|wget|invoke-webrequest|httpie)\b/iu;
const SECRET_REFERENCE_PATTERN = /\$\{\{\s*secrets\.([a-zA-Z0-9_]+)\s*\}\}/giu;
const URL_PATTERN = /https?:\/\/[^\s"')]+/giu;

function extractSecretReferences(value: string): string[] {
  const references = new Set<string>();
  for (const match of value.matchAll(SECRET_REFERENCE_PATTERN)) {
    const key = match[1]?.trim();
    if (!key) {
      continue;
    }
    references.add(key);
  }
  return Array.from(references);
}

function extractUrls(value: string): string[] {
  return Array.from(value.matchAll(URL_PATTERN), (match) => match[0] ?? "").filter(Boolean);
}

function isTrustedHost(hostname: string, trustedApiDomains: string[]): boolean {
  const normalizedHost = hostname.toLowerCase();
  return trustedApiDomains.some((domain) => {
    const normalizedDomain = domain.toLowerCase();
    return normalizedHost === normalizedDomain || normalizedHost.endsWith(`.${normalizedDomain}`);
  });
}

function hasOnlyTrustedUrls(run: string, trustedApiDomains: string[]): boolean {
  const urls = extractUrls(run);
  if (urls.length === 0) {
    return false;
  }

  return urls.every((url) => {
    try {
      const parsed = new URL(url);
      return isTrustedHost(parsed.hostname, trustedApiDomains);
    } catch {
      return false;
    }
  });
}

export function detectWorkflowSecretExfiltration(
  input: WorkflowSecretExfiltrationInput,
): Finding[] {
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
      if (!step.run || !OUTBOUND_COMMAND_PATTERN.test(step.run)) {
        return;
      }

      const referencedSecrets = extractSecretReferences(step.run);
      if (referencedSecrets.length === 0) {
        return;
      }

      if (hasOnlyTrustedUrls(step.run, input.trustedApiDomains)) {
        return;
      }

      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: ["secrets.", "curl", "wget", "http://", "https://"],
        fallbackValue: `${job.id} step references secrets in outbound network command`,
      });

      findings.push({
        rule_id: "workflow-secret-exfiltration",
        finding_id: `WORKFLOW_SECRET_EXFILTRATION-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity: "CRITICAL",
        category: "CI_PERMISSIONS",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].run` },
        description: "Workflow step sends secret context through outbound network command",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-200",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Avoid sending secrets through outbound shell commands",
          "Use trusted first-party actions with scoped credentials instead of ad-hoc exfil-prone scripts",
          "Restrict outbound domains and sanitize command arguments in privileged workflows",
        ],
        metadata: {
          referenced_secrets: referencedSecrets,
        },
        evidence: evidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
