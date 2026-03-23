import { buildFindingEvidence } from "../evidence.js";
import type { RuntimeMode } from "../../config.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowImpostorCommitInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  runtimeMode?: RuntimeMode;
}

interface ParsedUsesLine {
  lineNumber: number;
  column: number;
  rawLine: string;
  uses: string;
}

const GITHUB_API_HEADERS = {
  Accept: "application/vnd.github+json",
} as const;

function splitOwnerRepo(slug: string): { owner: string; repo: string } | null {
  const firstSlash = slug.indexOf("/");
  if (firstSlash < 0) {
    return null;
  }

  const owner = slug.slice(0, firstSlash);
  const repo = slug.slice(firstSlash + 1).split("/")[0];
  if (!owner || !repo) {
    return null;
  }

  return { owner, repo };
}

function isPinnedToCommit(ref: string): boolean {
  return /^[a-f0-9]{40}$/iu.test(ref.trim());
}

function parseRepositoryUses(value: string): { slug: string; ref: string } | null {
  const trimmed = value.trim();
  if (trimmed.startsWith("./") || trimmed.startsWith("docker://")) {
    return null;
  }

  const atIndex = trimmed.lastIndexOf("@");
  if (atIndex < 0) {
    return null;
  }

  const slug = trimmed.slice(0, atIndex).trim().replace(/\/+$/u, "").toLowerCase();
  const ref = trimmed.slice(atIndex + 1).trim();
  if (!slug.includes("/") || ref.length === 0) {
    return null;
  }

  return { slug, ref };
}

function parseUsesLine(line: string, lineNumber: number): ParsedUsesLine | null {
  const match = line.match(/^\s*(?:-\s*)?uses:\s*([^#]+?)(?:\s*#.*)?\s*$/iu);
  if (!match?.[1]) {
    return null;
  }

  const uses = match[1].trim();
  const usesColumn = line.indexOf("uses:");
  return {
    lineNumber,
    column: usesColumn >= 0 ? usesColumn + 1 : 1,
    rawLine: line,
    uses,
  };
}

async function fetchGitHubJson(url: string): Promise<unknown | null> {
  try {
    const response = await fetch(url, {
      headers: GITHUB_API_HEADERS,
    });

    if (!response.ok) {
      return null;
    }

    return (await response.json()) as unknown;
  } catch {
    return null;
  }
}

async function repositoryHasCommit(owner: string, repo: string, sha: string): Promise<boolean> {
  const url = `https://api.github.com/repos/${owner}/${repo}/commits/${encodeURIComponent(sha)}`;
  const payload = (await fetchGitHubJson(url)) as { sha?: string } | null;
  return typeof payload?.sha === "string" && payload.sha.length > 0;
}

export async function detectWorkflowImpostorCommit(
  input: WorkflowImpostorCommitInput,
): Promise<Finding[]> {
  if (!isGitHubWorkflowPath(input.filePath)) {
    return [];
  }

  if (!extractWorkflowFacts(input.parsed)) {
    return [];
  }

  const mode = input.runtimeMode ?? "offline";
  if (mode !== "online") {
    return [];
  }

  const findings: Finding[] = [];
  const lines = input.textContent.split(/\r?\n/u);

  for (const [index, line] of lines.entries()) {
    const parsedLine = parseUsesLine(line, index + 1);
    if (!parsedLine) {
      continue;
    }

    const parsedUses = parseRepositoryUses(parsedLine.uses);
    if (!parsedUses || !isPinnedToCommit(parsedUses.ref)) {
      continue;
    }

    const ownerRepo = splitOwnerRepo(parsedUses.slug);
    if (!ownerRepo) {
      continue;
    }

    if (await repositoryHasCommit(ownerRepo.owner, ownerRepo.repo, parsedUses.ref)) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [parsedLine.rawLine, parsedUses.ref, parsedUses.slug],
      fallbackValue: parsedLine.rawLine.trim(),
    });

    findings.push({
      rule_id: "workflow-impostor-commit",
      finding_id: `WORKFLOW_IMPOSTOR_COMMIT-${input.filePath}-${index + 1}`,
      severity: "HIGH",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { line: parsedLine.lineNumber, column: parsedLine.column },
      description: "Pinned action commit is not present in the referenced repository",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-829",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Pin the action to a commit that exists in the referenced repository and review the upstream history before updating",
      ],
      evidence: evidence?.evidence ?? parsedLine.rawLine.trim(),
      suppressed: false,
    });
  }

  return findings;
}
