import { copyFileSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import type { DiscoveryFormat } from "../types/discovery.js";
import type { ExplicitScanCandidate } from "./types.js";

const REPO_HOSTS = new Set(["github.com", "www.github.com", "gitlab.com", "www.gitlab.com", "bitbucket.org"]);
const RECURSIVE_ARTIFACT_FILE_NAMES = new Set([
  "skill.md",
  "agents.md",
  "claude.md",
  "codex.md",
  "plugins.json",
  "extensions.json",
  "marketplace.json",
  "product.json",
]);

export interface GitHubFileSource {
  repoUrl: string;
  filePath: string;
}

export function cleanupTempDir(path: string): void {
  rmSync(path, { recursive: true, force: true });
}

export function isLikelyHttpUrl(value: string): boolean {
  return /^https?:\/\//iu.test(value);
}

export function isLikelyGitRepoUrl(value: URL): boolean {
  if (!REPO_HOSTS.has(value.hostname.toLowerCase())) {
    return value.pathname.toLowerCase().endsWith(".git");
  }

  const pathname = value.pathname.replace(/\/+$/u, "");
  if (pathname.toLowerCase().endsWith(".git")) {
    return true;
  }
  if (/(?:^|\/)(blob|raw|tree)\//iu.test(pathname)) {
    return false;
  }

  const segments = pathname.split("/").filter((segment) => segment.length > 0);
  return segments.length === 2;
}

export function sanitizePathSegment(value: string): string {
  const sanitized = value.replace(/[^a-z0-9._-]/giu, "-");
  return sanitized.length > 0 ? sanitized : "artifact";
}

export function preserveTailSegments(pathname: string, count: number): string {
  const segments = pathname
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) => sanitizePathSegment(segment));
  if (segments.length === 0) {
    return "artifact";
  }
  return join(...segments.slice(-count));
}

export function inferLocalFileStagePath(absolutePath: string): string {
  const fileName = basename(absolutePath);
  const lower = fileName.toLowerCase();

  if (lower === "product.json") {
    return join(".kiro", "product.json");
  }

  if (lower === "skill.md" || lower === "plugins.json" || lower === "extensions.json" || lower === "marketplace.json") {
    return preserveTailSegments(absolutePath, 2);
  }

  return fileName;
}

export function inferRemoteFileStagePath(url: URL): string {
  const fileName = basename(url.pathname) || "artifact";
  const lower = fileName.toLowerCase();

  if (lower === "product.json") {
    return join(".kiro", "product.json");
  }

  if (lower === "skill.md" || lower === "plugins.json" || lower === "extensions.json" || lower === "marketplace.json") {
    return preserveTailSegments(url.pathname, 3);
  }

  return sanitizePathSegment(fileName);
}

export function shouldStageContainingFolder(filePath: string): boolean {
  const fileName = basename(filePath).toLowerCase();
  return RECURSIVE_ARTIFACT_FILE_NAMES.has(fileName) || fileName.endsWith(".mdc");
}

export function inferTextLikeFormat(filePath: string): DiscoveryFormat | null {
  const lower = basename(filePath).toLowerCase();

  if (lower === ".env" || lower.endsWith(".env")) {
    return "dotenv";
  }
  if (lower.endsWith(".json")) {
    return "json";
  }
  if (lower.endsWith(".jsonc")) {
    return "jsonc";
  }
  if (lower.endsWith(".toml")) {
    return "toml";
  }
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) {
    return "yaml";
  }
  if (lower.endsWith(".md") || lower.endsWith(".mdc")) {
    return "markdown";
  }
  if (
    lower.endsWith(".txt") ||
    lower.endsWith(".sh") ||
    lower.endsWith(".bash") ||
    lower.endsWith(".zsh") ||
    lower.endsWith(".fish") ||
    lower.endsWith(".ps1") ||
    lower.endsWith(".js") ||
    lower.endsWith(".mjs") ||
    lower.endsWith(".cjs") ||
    lower.endsWith(".ts") ||
    lower.endsWith(".py")
  ) {
    return "text";
  }

  return null;
}

export function inferToolFromReportPath(reportPath: string): string {
  const lower = reportPath.toLowerCase();
  if (lower.endsWith("skill.md") || lower.endsWith("codex.md")) {
    return "codex-cli";
  }
  if (lower.endsWith("agents.md") || lower.endsWith("claude.md")) {
    return "claude-code";
  }
  if (lower.endsWith("plugins.json")) {
    return lower.includes(".claude/") ? "claude-code" : "opencode";
  }
  if (lower.endsWith("extensions.json")) {
    if (lower.includes(".zed/")) {
      return "zed";
    }
    if (lower.includes(".gemini/")) {
      return "gemini-cli";
    }
    return "vscode";
  }
  if (lower.endsWith("marketplace.json")) {
    return lower.includes(".cline/") ? "cline" : "roo-code";
  }
  if (lower.endsWith("product.json")) {
    return "kiro";
  }
  if (lower.endsWith(".mdc")) {
    return "cursor";
  }
  return "codex-cli";
}

export function copyDirectoryRecursive(sourceDir: string, destinationDir: string): void {
  mkdirSync(destinationDir, { recursive: true });
  for (const entry of readdirSync(sourceDir, { withFileTypes: true })) {
    if (entry.name === ".git") {
      continue;
    }

    const sourcePath = join(sourceDir, entry.name);
    const destinationPath = join(destinationDir, entry.name);
    if (entry.isDirectory()) {
      copyDirectoryRecursive(sourcePath, destinationPath);
      continue;
    }
    if (entry.isFile()) {
      mkdirSync(dirname(destinationPath), { recursive: true });
      copyFileSync(sourcePath, destinationPath);
    }
  }
}

export function collectExplicitCandidates(root: string): ExplicitScanCandidate[] {
  const candidates: ExplicitScanCandidate[] = [];
  const queue = [root];

  while (queue.length > 0) {
    const current = queue.pop();
    if (!current) {
      continue;
    }

    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absolutePath = join(current, entry.name);
      if (entry.isDirectory()) {
        queue.push(absolutePath);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }

      const reportPath = absolutePath.slice(root.length + 1).replaceAll("\\", "/");
      const format = inferTextLikeFormat(reportPath);
      if (!format) {
        continue;
      }

      candidates.push({
        reportPath,
        absolutePath,
        format,
        tool: inferToolFromReportPath(reportPath),
      });
    }
  }

  return candidates.sort((left, right) => {
    const depthDifference = left.reportPath.split("/").length - right.reportPath.split("/").length;
    if (depthDifference !== 0) {
      return depthDifference;
    }
    return left.reportPath.localeCompare(right.reportPath);
  });
}

export function parseGitHubFileSource(rawTarget: string): GitHubFileSource | null {
  let url: URL;
  try {
    url = new URL(rawTarget);
  } catch {
    return null;
  }

  if (url.hostname.toLowerCase() === "raw.githubusercontent.com") {
    const segments = url.pathname.split("/").filter((segment) => segment.length > 0);
    if (segments.length < 4) {
      return null;
    }
    const [owner, repo, _branch, ...fileSegments] = segments;
    return {
      repoUrl: `https://github.com/${owner}/${repo}.git`,
      filePath: fileSegments.join("/"),
    };
  }

  if (url.hostname.toLowerCase() === "github.com") {
    const segments = url.pathname.split("/").filter((segment) => segment.length > 0);
    if (segments.length < 5) {
      return null;
    }
    const [owner, repo, marker, _branch, ...fileSegments] = segments;
    if (marker !== "blob" && marker !== "raw") {
      return null;
    }
    return {
      repoUrl: `https://github.com/${owner}/${repo}.git`,
      filePath: fileSegments.join("/"),
    };
  }

  return null;
}
