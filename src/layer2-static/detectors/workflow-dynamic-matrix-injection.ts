import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { collectUntrustedReachableJobIds } from "../workflow/analysis.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowDynamicMatrixInjectionInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const MATRIX_REFERENCE_PATTERN = /\$\{\{\s*matrix\.[^}]+\}\}/iu;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isUntrustedDynamicMatrixExpression(value: string): boolean {
  const normalized = value.toLowerCase();
  if (!normalized.includes("${{")) {
    return false;
  }

  const untrustedEventRefs = [
    "github.event.pull_request.",
    "github.event.issue.",
    "github.event.comment.",
    "github.event.review.",
    "github.event.discussion.",
    "github.event.head_commit.",
  ];

  return untrustedEventRefs.some((ref) => normalized.includes(ref));
}

function isStaticFromJsonExpression(value: string): boolean {
  const normalized = value.toLowerCase().replace(/\s+/gu, "");
  return (
    normalized.includes("fromjson('") ||
    normalized.includes('fromjson("') ||
    normalized.includes("fromjson(`")
  );
}

function hasMatrixAllowListValidation(condition: string | undefined): boolean {
  if (!condition) {
    return false;
  }
  const normalized = condition.toLowerCase();
  return normalized.includes("contains(fromjson(") && normalized.includes("matrix.");
}

export function detectWorkflowDynamicMatrixInjection(
  input: WorkflowDynamicMatrixInjectionInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const root = asRecord(input.parsed);
  const jobsRecord = root ? asRecord(root.jobs) : null;
  if (!jobsRecord) {
    return [];
  }

  const reachableJobIds = collectUntrustedReachableJobIds(facts);
  if (reachableJobIds.size === 0) {
    return [];
  }

  const findings: Finding[] = [];

  facts.jobs.forEach((job, jobIndex) => {
    if (!reachableJobIds.has(job.id)) {
      return;
    }

    const rawJob = asRecord(jobsRecord[job.id]);
    if (!rawJob) {
      return;
    }
    const strategyRecord = asRecord(rawJob.strategy);
    const matrixExpression = strategyRecord ? asString(strategyRecord.matrix) : undefined;
    if (!matrixExpression || !isUntrustedDynamicMatrixExpression(matrixExpression)) {
      return;
    }
    if (
      isStaticFromJsonExpression(matrixExpression) &&
      !matrixExpression.includes("github.event.")
    ) {
      return;
    }

    const hasAllowList = hasMatrixAllowListValidation(job.if);
    const severity = hasAllowList ? "MEDIUM" : "HIGH";

    const matrixEvidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: ["strategy:", "matrix:", "fromJSON", "github.event"],
      fallbackValue: `${job.id} strategy.matrix is built from untrusted event data`,
    });

    findings.push({
      rule_id: "workflow-dynamic-matrix-injection",
      finding_id: `WORKFLOW_DYNAMIC_MATRIX_INJECTION-${input.filePath}-${jobIndex}`,
      severity,
      category: "CI_TEMPLATE_INJECTION",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${job.id}.strategy.matrix` },
      description: "Workflow strategy.matrix is derived from untrusted event payload content",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-94",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Avoid building strategy.matrix from attacker-controlled event fields",
        "Use static allow-list matrices or validate and sanitize dynamic matrix payloads",
        "Do not interpolate untrusted matrix values directly into shell commands",
      ],
      metadata: {
        risk_tags: [hasAllowList ? "allow-list-guard" : "no-allow-list-guard"],
        origin: "workflow-audit",
      },
      evidence: matrixEvidence?.evidence ?? null,
      suppressed: false,
    });

    job.steps.forEach((step, stepIndex) => {
      if (!step.run || !MATRIX_REFERENCE_PATTERN.test(step.run)) {
        return;
      }

      const runEvidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: [step.run],
        fallbackValue: `${job.id} run step interpolates matrix value in shell command`,
      });

      findings.push({
        rule_id: "workflow-dynamic-matrix-injection",
        finding_id: `WORKFLOW_DYNAMIC_MATRIX_INJECTION_RUN-${input.filePath}-${jobIndex}-${stepIndex}`,
        severity,
        category: "CI_TEMPLATE_INJECTION",
        layer: "L2",
        file_path: input.filePath,
        location: { field: `jobs.${job.id}.steps[${stepIndex}].run` },
        description:
          "Workflow run step interpolates dynamic matrix values sourced from untrusted event data",
        affected_tools: ["github-actions"],
        cve: null,
        owasp: ["ASI02"],
        cwe: "CWE-94",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [
          "Validate matrix values against explicit allow-lists before shell interpolation",
          "Move untrusted values into strictly validated variables before command execution",
        ],
        metadata: {
          risk_tags: [hasAllowList ? "allow-list-guard" : "no-allow-list-guard"],
          origin: "workflow-audit",
        },
        evidence: runEvidence?.evidence ?? null,
        suppressed: false,
      });
    });
  });

  return findings;
}
