import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowUnpinnedImagesInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface ImageTarget {
  field: string;
  image: string;
}

const SHA256_DIGEST_RE = /@sha256:[a-f0-9]{64}$/iu;
const MUTABLE_LATEST_TAG = "latest";

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function getImageTag(image: string): string | null {
  const trimmed = image.trim();
  if (trimmed.length === 0 || trimmed.includes("@")) {
    return null;
  }

  const lastSlash = trimmed.lastIndexOf("/");
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon <= lastSlash) {
    return null;
  }

  const tag = trimmed.slice(lastColon + 1).trim();
  return tag.length > 0 ? tag : null;
}

function isShaPinned(image: string): boolean {
  return SHA256_DIGEST_RE.test(image.trim());
}

function gatherImageTargets(parsed: unknown): ImageTarget[] {
  const root = asRecord(parsed);
  const jobsRecord = asRecord(root?.jobs);
  if (!jobsRecord) {
    return [];
  }

  const targets: ImageTarget[] = [];

  for (const [jobId, jobValue] of Object.entries(jobsRecord)) {
    const jobRecord = asRecord(jobValue);
    if (!jobRecord) {
      continue;
    }

    const containerRecord = asRecord(jobRecord.container);
    if (typeof containerRecord?.image === "string") {
      targets.push({
        field: `jobs.${jobId}.container.image`,
        image: containerRecord.image,
      });
    }

    const servicesRecord = asRecord(jobRecord.services);
    if (servicesRecord) {
      for (const [serviceName, serviceValue] of Object.entries(servicesRecord)) {
        const serviceRecord = asRecord(serviceValue);
        if (typeof serviceRecord?.image === "string") {
          targets.push({
            field: `jobs.${jobId}.services.${serviceName}.image`,
            image: serviceRecord.image,
          });
        }
      }
    }
  }

  return targets;
}

export function detectWorkflowUnpinnedImages(input: WorkflowUnpinnedImagesInput): Finding[] {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  if (!extractWorkflowFacts(input.parsed)) {
    return [];
  }

  const findings: Finding[] = [];

  for (const target of gatherImageTargets(input.parsed)) {
    const trimmedImage = target.image.trim();
    if (trimmedImage.length === 0 || isShaPinned(trimmedImage)) {
      continue;
    }

    const tag = getImageTag(trimmedImage);
    if (tag !== null && tag !== MUTABLE_LATEST_TAG) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [trimmedImage, "image:"],
      fallbackValue: trimmedImage,
    });

    findings.push({
      rule_id: "workflow-unpinned-images",
      finding_id: `WORKFLOW_UNPINNED_IMAGES-${input.filePath}-${target.field}`,
      severity: "HIGH",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { field: target.field },
      description:
        tag === MUTABLE_LATEST_TAG
          ? "Workflow container image uses the mutable latest tag"
          : "Workflow container image is not pinned to a SHA256 digest",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-829",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Pin container images to immutable sha256 digests instead of mutable tags",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
