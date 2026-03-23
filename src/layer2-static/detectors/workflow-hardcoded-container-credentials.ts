import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowHardcodedContainerCredentialsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface ImageTarget {
  field: string;
  image: string;
}

const CREDENTIAL_IN_IMAGE_PATTERNS = [/:\/\/[^/\s:@]+:[^@\s]+@/iu, /:[^@\s]+@(?!sha256:)/iu];

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function gatherImageTargets(parsed: unknown): ImageTarget[] {
  const root = asRecord(parsed);
  const jobs = asRecord(root?.jobs);
  if (!jobs) {
    return [];
  }

  const targets: ImageTarget[] = [];
  for (const [jobId, jobValue] of Object.entries(jobs)) {
    const job = asRecord(jobValue);
    if (!job) {
      continue;
    }

    const container = asRecord(job.container);
    if (typeof container?.image === "string") {
      targets.push({
        field: `jobs.${jobId}.container.image`,
        image: container.image,
      });
    }

    const services = asRecord(job.services);
    if (!services) {
      continue;
    }

    for (const [serviceName, serviceValue] of Object.entries(services)) {
      const service = asRecord(serviceValue);
      if (typeof service?.image === "string") {
        targets.push({
          field: `jobs.${jobId}.services.${serviceName}.image`,
          image: service.image,
        });
      }
    }
  }

  return targets;
}

function hasEmbeddedCredentials(image: string): boolean {
  const value = image.trim();
  return CREDENTIAL_IN_IMAGE_PATTERNS.some((pattern) => pattern.test(value));
}

export function detectWorkflowHardcodedContainerCredentials(
  input: WorkflowHardcodedContainerCredentialsInput,
): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  const facts = extractWorkflowFacts(input.parsed);
  if (!facts) {
    return [];
  }

  const findings: Finding[] = [];
  for (const target of gatherImageTargets(input.parsed)) {
    if (!hasEmbeddedCredentials(target.image)) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [target.image, "image:"],
      fallbackValue: target.image,
    });

    findings.push({
      rule_id: "hardcoded-container-credentials",
      finding_id: `HARDCODED_CONTAINER_CREDENTIALS-${input.filePath}-${target.field}`,
      severity: "HIGH",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { field: target.field },
      description: "Container image reference appears to embed static credentials",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-798",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Remove embedded credentials from image references and use short-lived registry auth",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
