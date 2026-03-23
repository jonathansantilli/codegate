import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import {
  collectArtifactTransferEdges,
  collectUntrustedReachableJobIds,
} from "../workflow/analysis.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowArtifactTrustChainInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function hasWritePermission(value: unknown): boolean {
  if (typeof value === "string") {
    return value.trim().toLowerCase() === "write-all";
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  return Object.values(value as Record<string, unknown>).some(
    (permission) => typeof permission === "string" && permission.trim().toLowerCase() === "write",
  );
}

function hasInheritedSecrets(secrets: unknown): boolean {
  return typeof secrets === "string" && secrets.trim().toLowerCase() === "inherit";
}

function hasExecutableRunStep(jobSteps: Array<{ run?: string }>): boolean {
  return jobSteps.some((step) => typeof step.run === "string" && step.run.trim().length > 0);
}

export function detectWorkflowArtifactTrustChain(
  input: WorkflowArtifactTrustChainInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const untrustedJobIds = collectUntrustedReachableJobIds(facts);
  if (untrustedJobIds.size === 0) {
    return [];
  }

  const workflowHasWritePermissions = hasWritePermission(facts.workflowPermissions);
  const jobsById = new Map(facts.jobs.map((job) => [job.id, job]));
  const findings: Finding[] = [];
  const dedupe = new Set<string>();

  for (const edge of collectArtifactTransferEdges(facts)) {
    if (!untrustedJobIds.has(edge.producerJobId)) {
      continue;
    }

    const consumerJob = jobsById.get(edge.consumerJobId);
    if (!consumerJob) {
      continue;
    }

    const consumerPrivileged =
      workflowHasWritePermissions ||
      hasWritePermission(consumerJob.permissions) ||
      hasInheritedSecrets(consumerJob.secrets);

    if (!consumerPrivileged || !hasExecutableRunStep(consumerJob.steps)) {
      continue;
    }

    const dedupeKey = `${edge.producerJobId}|${edge.consumerJobId}|${edge.artifactName}`;
    if (dedupe.has(dedupeKey)) {
      continue;
    }
    dedupe.add(dedupeKey);

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [
        "actions/upload-artifact",
        "actions/download-artifact",
        edge.artifactName,
        "pull_request",
      ],
      fallbackValue: `${edge.consumerJobId} consumes artifact ${edge.artifactName} from untrusted producer ${edge.producerJobId}`,
    });

    findings.push({
      rule_id: "workflow-artifact-trust-chain",
      finding_id: `WORKFLOW_ARTIFACT_TRUST_CHAIN-${input.filePath}-${edge.producerJobId}-${edge.consumerJobId}-${edge.artifactName}`,
      severity: edge.consumerDownloadsAll ? "CRITICAL" : "HIGH",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${edge.consumerJobId}.steps[${edge.consumerStepIndex}]` },
      description:
        "Privileged job executes after downloading artifacts produced in an untrusted workflow path",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-829",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Separate untrusted artifact production from privileged execution jobs",
        "Require integrity verification before consuming downloaded artifacts",
        "Avoid executing downloaded artifacts in jobs with write tokens or inherited secrets",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
