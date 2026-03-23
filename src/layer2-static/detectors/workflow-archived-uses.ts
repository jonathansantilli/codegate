import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowArchivedUsesInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface RepositoryUseTarget {
  raw: string;
  owner: string;
  repo: string;
}

type FetchFn = typeof fetch;

const archivedRepoCacheByFetch = new WeakMap<FetchFn, Map<string, boolean>>();
const GITHUB_API_HEADERS = {
  Accept: "application/vnd.github+json",
  "User-Agent": "CodeGate",
} as const;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function isExternalRepositoryUse(value: string): boolean {
  return value.startsWith("./") || value.startsWith("../") || value.startsWith("docker://");
}

function trimTrailingSlashes(value: string): string {
  return value.replace(/\/+$/u, "");
}

function parseRepositoryUses(value: string): RepositoryUseTarget | null {
  const trimmed = value.trim();
  if (trimmed.length === 0 || isExternalRepositoryUse(trimmed)) {
    return null;
  }

  const atIndex = trimmed.lastIndexOf("@");
  if (atIndex < 0) {
    return null;
  }

  const slug = trimTrailingSlashes(trimmed.slice(0, atIndex).trim());
  const [owner, repo] = slug.split("/");
  if (!owner || !repo) {
    return null;
  }

  return {
    raw: trimmed,
    owner: owner.toLowerCase(),
    repo: repo.toLowerCase(),
  };
}

async function isArchivedRepository(owner: string, repo: string): Promise<boolean> {
  const fetchFn = globalThis.fetch;
  if (typeof fetchFn !== "function") {
    return false;
  }

  let cache = archivedRepoCacheByFetch.get(fetchFn);
  if (!cache) {
    cache = new Map<string, boolean>();
    archivedRepoCacheByFetch.set(fetchFn, cache);
  }

  const cacheKey = `${owner}/${repo}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }

  try {
    const response = await fetchFn(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
      {
        headers: GITHUB_API_HEADERS,
      },
    );

    if (!response.ok) {
      cache.set(cacheKey, false);
      return false;
    }

    const payload = (await response.json()) as { archived?: unknown } | null;
    const archived = Boolean(payload && typeof payload === "object" && payload.archived === true);
    cache.set(cacheKey, archived);
    return archived;
  } catch {
    return false;
  }
}

function gatherUsesTargets(parsed: unknown): Array<RepositoryUseTarget & { field: string }> {
  const root = asRecord(parsed);
  const jobsRecord = asRecord(root?.jobs);
  if (!jobsRecord) {
    return [];
  }

  const targets: Array<RepositoryUseTarget & { field: string }> = [];
  const addTarget = (uses: string, field: string): void => {
    const parsedUses = parseRepositoryUses(uses);
    if (parsedUses) {
      targets.push({
        ...parsedUses,
        field,
      });
    }
  };

  for (const [jobId, jobValue] of Object.entries(jobsRecord)) {
    const jobRecord = asRecord(jobValue);
    if (!jobRecord) {
      continue;
    }

    if (typeof jobRecord.uses === "string") {
      addTarget(jobRecord.uses, `jobs.${jobId}.uses`);
    }

    const steps = Array.isArray(jobRecord.steps) ? jobRecord.steps : [];
    steps.forEach((step, stepIndex) => {
      const stepRecord = asRecord(step);
      if (stepRecord && typeof stepRecord.uses === "string") {
        addTarget(stepRecord.uses, `jobs.${jobId}.steps[${stepIndex}].uses`);
      }
    });
  }

  return targets;
}

export async function detectWorkflowArchivedUses(
  input: WorkflowArchivedUsesInput,
): Promise<Finding[]> {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  if (!extractWorkflowFacts(input.parsed)) {
    return [];
  }

  const targets = gatherUsesTargets(input.parsed);
  const findings: Finding[] = [];

  for (const target of targets) {
    if (!(await isArchivedRepository(target.owner, target.repo))) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [target.raw, `${target.owner}/${target.repo}`],
      fallbackValue: target.raw,
    });

    findings.push({
      rule_id: "workflow-archived-uses",
      finding_id: `WORKFLOW_ARCHIVED_USES-${input.filePath}-${target.field}`,
      severity: "MEDIUM",
      category: "CI_VULNERABLE_ACTION",
      layer: "L2",
      file_path: input.filePath,
      location: { field: target.field },
      description: "Workflow action or reusable workflow comes from an archived repository",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-829",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Replace the archived repository reference with an actively maintained alternative",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
