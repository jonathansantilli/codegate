import { buildFindingEvidence } from "../evidence.js";
import type { RuntimeMode } from "../../config.js";
import type { Finding } from "../../types/finding.js";
import { extractWorkflowFacts, isGitHubWorkflowPath } from "../workflow/parser.js";

export interface WorkflowRefVersionMismatchInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  runtimeMode?: RuntimeMode;
}

const VERSION_COMMENT_PATTERNS = [
  /#\s*tag\s*=\s*(v\d+(?:\.\d+)*(?:\.\d+)?)/iu,
  /#\s*(v\d+(?:\.\d+)*(?:\.\d+)?)/iu,
  /#\s*tag\s*=\s*(\d+(?:\.\d+)*(?:\.\d+)?)/iu,
  /#\s*(?:version|ver)\s*[:=]\s*(v?\d+(?:\.\d+)*(?:\.\d+)?)/iu,
];
const GITHUB_API_HEADERS = {
  Accept: "application/vnd.github+json",
} as const;
const MAX_TAG_DEPTH = 8;

interface ParsedUsesLine {
  lineNumber: number;
  column: number;
  rawLine: string;
  uses: string;
  versionComment: string;
}

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

function extractVersionComment(line: string): string | null {
  for (const pattern of VERSION_COMMENT_PATTERNS) {
    const match = line.match(pattern);
    if (match?.[1]) {
      return match[1];
    }
  }

  return null;
}

function parseUsesLine(line: string, lineNumber: number): ParsedUsesLine | null {
  const match = line.match(/^\s*(?:-\s*)?uses:\s*([^#]+?)(?:\s*#\s*(.+))?\s*$/iu);
  if (!match?.[1]) {
    return null;
  }

  const uses = match[1].trim();
  const versionComment = extractVersionComment(line);
  if (!versionComment) {
    return null;
  }

  const usesColumn = line.indexOf("uses:");
  return {
    lineNumber,
    column: usesColumn >= 0 ? usesColumn + 1 : 1,
    rawLine: line,
    uses,
    versionComment,
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

async function resolveTagCommitSha(
  owner: string,
  repo: string,
  tag: string,
): Promise<string | null> {
  const normalizedTag = tag.trim();
  if (normalizedTag.length === 0) {
    return null;
  }

  const refUrl = `https://api.github.com/repos/${owner}/${repo}/git/ref/tags/${encodeURIComponent(
    normalizedTag,
  )}`;
  const ref = (await fetchGitHubJson(refUrl)) as {
    object?: { type?: string; sha?: string };
  } | null;
  if (!ref?.object?.sha || !ref.object.type) {
    return null;
  }

  if (ref.object.type === "commit") {
    return ref.object.sha;
  }

  if (ref.object.type !== "tag") {
    return null;
  }

  const seenObjects = new Set<string>([ref.object.sha]);
  let tagObjectSha = ref.object.sha;

  for (let depth = 0; depth < MAX_TAG_DEPTH; depth += 1) {
    const tagUrl = `https://api.github.com/repos/${owner}/${repo}/git/tags/${tagObjectSha}`;
    const tagObject = (await fetchGitHubJson(tagUrl)) as {
      object?: { type?: string; sha?: string };
    } | null;

    if (!tagObject?.object?.sha || !tagObject.object.type) {
      return null;
    }

    if (tagObject.object.type === "commit") {
      return tagObject.object.sha;
    }

    if (tagObject.object.type !== "tag" || seenObjects.has(tagObject.object.sha)) {
      return null;
    }

    seenObjects.add(tagObject.object.sha);
    tagObjectSha = tagObject.object.sha;
  }

  return null;
}

export async function detectWorkflowRefVersionMismatch(
  input: WorkflowRefVersionMismatchInput,
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

    const matchedCommit = await resolveTagCommitSha(
      ownerRepo.owner,
      ownerRepo.repo,
      parsedLine.versionComment,
    );

    if (!matchedCommit || matchedCommit === parsedUses.ref) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [parsedLine.rawLine, parsedLine.versionComment, parsedUses.ref],
      fallbackValue: parsedLine.rawLine.trim(),
    });

    findings.push({
      rule_id: "workflow-ref-version-mismatch",
      finding_id: `WORKFLOW_REF_VERSION_MISMATCH-${input.filePath}-${index + 1}`,
      severity: "MEDIUM",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { line: parsedLine.lineNumber, column: parsedLine.column },
      description: "Hash-pinned action commit does not match its version comment tag",
      affected_tools: ["github-actions"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-829",
      confidence: "HIGH",
      fixable: false,
      remediation_actions: [
        "Update the version comment to match the pinned commit or repin the action to the intended release tag",
      ],
      evidence: evidence?.evidence ?? parsedLine.rawLine.trim(),
      suppressed: false,
    });
  }

  return findings;
}
