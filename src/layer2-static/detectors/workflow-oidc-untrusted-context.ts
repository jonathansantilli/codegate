import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence } from "../evidence.js";
import { collectUntrustedReachableJobIds } from "../workflow/analysis.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowOidcUntrustedContextInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

const CLOUD_AUTH_ACTIONS = new Set([
  "aws-actions/configure-aws-credentials",
  "azure/login",
  "google-github-actions/auth",
]);

const AUDIENCE_KEYS = new Set(["audience", "token_audience", "id_token_audience"]);

function hasWritePermission(value: unknown): boolean {
  if (typeof value === "string") {
    return value.trim().toLowerCase() === "write-all";
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  return Object.entries(value as Record<string, unknown>).some(([key, permission]) => {
    if (key.trim().toLowerCase() === "id-token") {
      return false;
    }
    if (typeof permission !== "string") {
      return false;
    }
    return permission.trim().toLowerCase() === "write";
  });
}

function hasIdTokenWrite(value: unknown): boolean {
  if (typeof value === "string") {
    return value.trim().toLowerCase() === "write-all";
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const record = value as Record<string, unknown>;
  const idTokenPermission = record["id-token"];
  return (
    typeof idTokenPermission === "string" && idTokenPermission.trim().toLowerCase() === "write"
  );
}

function normalizeUses(value: string | undefined): string | null {
  if (!value) {
    return null;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized.length === 0) {
    return null;
  }
  const atIndex = normalized.indexOf("@");
  return atIndex === -1 ? normalized : normalized.slice(0, atIndex);
}

function hasCloudOidcAuthStep(jobSteps: Array<{ uses?: string }>): boolean {
  return jobSteps.some((step) => {
    const normalizedUses = normalizeUses(step.uses);
    return normalizedUses ? CLOUD_AUTH_ACTIONS.has(normalizedUses) : false;
  });
}

function hasAudienceConstraint(jobSteps: Array<{ with?: Record<string, string> }>): boolean {
  return jobSteps.some((step) => {
    const withRecord = step.with;
    if (!withRecord) {
      return false;
    }

    return Object.entries(withRecord).some(([key, value]) => {
      if (!AUDIENCE_KEYS.has(key.trim().toLowerCase())) {
        return false;
      }
      return value.trim().length > 0;
    });
  });
}

function hasActorConstraint(condition: string): boolean {
  const normalized = condition.toLowerCase();
  return (
    normalized.includes("github.actor") ||
    normalized.includes("github.triggering_actor") ||
    normalized.includes("github.event.pull_request.user.login")
  );
}

function hasRepositoryOrRefConstraint(condition: string): boolean {
  const normalized = condition.toLowerCase();
  return (
    normalized.includes("github.repository") ||
    normalized.includes("github.event.pull_request.head.repo.full_name") ||
    normalized.includes("github.event.pull_request.head.repo.fork") ||
    normalized.includes("github.ref") ||
    normalized.includes("github.base_ref") ||
    normalized.includes("github.event.pull_request.base.ref")
  );
}

function hasStrictTrustChecks(condition: string | undefined): boolean {
  if (!condition) {
    return false;
  }
  return hasActorConstraint(condition) && hasRepositoryOrRefConstraint(condition);
}

export function detectWorkflowOidcUntrustedContext(
  input: WorkflowOidcUntrustedContextInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const reachableJobIds = collectUntrustedReachableJobIds(facts);
  if (reachableJobIds.size === 0) {
    return [];
  }

  const findings: Finding[] = [];
  const workflowHasIdTokenWrite = hasIdTokenWrite(facts.workflowPermissions);

  facts.jobs.forEach((job, jobIndex) => {
    if (!reachableJobIds.has(job.id)) {
      return;
    }

    const jobHasIdTokenWrite = workflowHasIdTokenWrite || hasIdTokenWrite(job.permissions);
    if (!jobHasIdTokenWrite) {
      return;
    }

    const strictTrustChecks = hasStrictTrustChecks(job.if);
    const cloudAuthDetected = hasCloudOidcAuthStep(job.steps);
    const hasAudience = hasAudienceConstraint(job.steps);

    if (strictTrustChecks && hasAudience) {
      return;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [
        "id-token: write",
        "permissions",
        "audience",
        "github.actor",
        "github.repository",
      ],
      fallbackValue: `${job.id} enables id-token write in untrusted trigger context`,
    });

    findings.push({
      rule_id: "workflow-oidc-untrusted-context",
      finding_id: `WORKFLOW_OIDC_UNTRUSTED_CONTEXT-${input.filePath}-${jobIndex}`,
      severity:
        hasWritePermission(job.permissions) || hasWritePermission(facts.workflowPermissions)
          ? "CRITICAL"
          : "HIGH",
      category: "CI_PERMISSIONS",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `jobs.${job.id}.permissions.id-token` },
      description:
        "Workflow enables OIDC token minting in an untrusted trigger context without strict trust boundaries",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-284",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Restrict id-token: write to trusted branches or trusted workflow_call boundaries",
        "Require explicit actor and repository/ref checks on untrusted triggers",
        cloudAuthDetected
          ? "Configure explicit audience constraints for cloud authentication actions"
          : "Add audience constraints and scoped trust conditions before minting OIDC tokens",
      ],
      metadata: {
        risk_tags: [
          strictTrustChecks ? "strict-trust-checks" : "missing-strict-trust-checks",
          hasAudience ? "audience-constrained" : "missing-audience-constraint",
          cloudAuthDetected ? "cloud-auth-step" : "generic-oidc",
        ],
        origin: "workflow-audit",
      },
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  });

  return findings;
}
