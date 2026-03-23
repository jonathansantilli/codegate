import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowStaleActionRefsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface RepositoryUseTarget {
  raw: string;
  owner: string;
  repo: string;
  ref: string;
}

type FetchFn = typeof fetch;

const staleActionCacheByFetch = new WeakMap<FetchFn, Map<string, boolean>>();
const GITHUB_API_HEADERS = {
  Accept: "application/vnd.github+json",
  "User-Agent": "CodeGate",
} as const;
const MAX_TAG_PAGES = 10;

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
  const ref = trimmed.slice(atIndex + 1).trim();
  const [owner, repo] = slug.split("/");
  if (!owner || !repo || ref.length === 0) {
    return null;
  }

  return {
    raw: trimmed,
    owner: owner.toLowerCase(),
    repo: repo.toLowerCase(),
    ref,
  };
}

function isCommitSha(ref: string): boolean {
  return /^[a-f0-9]{40}$/iu.test(ref.trim());
}

async function commitPointsToTag(owner: string, repo: string, ref: string): Promise<boolean> {
  const fetchFn = globalThis.fetch;
  if (typeof fetchFn !== "function") {
    return false;
  }

  let cache = staleActionCacheByFetch.get(fetchFn);
  if (!cache) {
    cache = new Map<string, boolean>();
    staleActionCacheByFetch.set(fetchFn, cache);
  }

  const normalizedRef = ref.toLowerCase();
  const cacheKey = `${owner}/${repo}@${normalizedRef}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }

  try {
    for (let page = 1; page <= MAX_TAG_PAGES; page += 1) {
      const url = new URL(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/tags`,
      );
      url.searchParams.set("per_page", "100");
      url.searchParams.set("page", String(page));

      const response = await fetchFn(url, {
        headers: GITHUB_API_HEADERS,
      });

      if (!response.ok) {
        cache.set(cacheKey, false);
        return false;
      }

      const payload = (await response.json()) as unknown;
      if (!Array.isArray(payload)) {
        cache.set(cacheKey, false);
        return false;
      }

      for (const tag of payload) {
        const tagRecord = asRecord(tag);
        const commitRecord = asRecord(tagRecord?.commit);
        const tagSha = typeof commitRecord?.sha === "string" ? commitRecord.sha : undefined;
        if (tagSha && tagSha.toLowerCase() === normalizedRef) {
          cache.set(cacheKey, true);
          return true;
        }
      }

      const linkHeader = response.headers.get("link") ?? "";
      if (!linkHeader.includes('rel="next"') || payload.length < 100) {
        break;
      }
    }
  } catch {
    return false;
  }

  cache.set(cacheKey, false);
  return false;
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

export async function detectWorkflowStaleActionRefs(
  input: WorkflowStaleActionRefsInput,
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
    if (!isCommitSha(target.ref)) {
      continue;
    }

    if (await commitPointsToTag(target.owner, target.repo, target.ref)) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [target.raw, target.ref],
      fallbackValue: target.raw,
    });

    findings.push({
      rule_id: "workflow-stale-action-refs",
      finding_id: `WORKFLOW_STALE_ACTION_REFS-${input.filePath}-${target.field}`,
      severity: "LOW",
      category: "CI_VULNERABLE_ACTION",
      layer: "L2",
      file_path: input.filePath,
      location: { field: target.field },
      description: "Workflow action reference pins a commit hash that does not resolve to a tag",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-829",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Pin the action to a commit hash that corresponds to a release tag, or document why the raw commit is required",
      ],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  }

  return findings;
}
