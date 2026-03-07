import { copyFileSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  cleanupTempDir,
  collectExplicitCandidates,
  copyDirectoryRecursive,
  inferLocalFileStagePath,
  inferRemoteFileStagePath,
  parseGitHubFileSource,
  preserveTailSegments,
  shouldStageContainingFolder,
} from "./helpers.js";
import type { ResolvedScanTarget } from "./types.js";

function cloneRepository(source: string, destination: string): void {
  const result = spawnSync("git", ["clone", "--depth", "1", "--filter=blob:none", source, destination], {
    encoding: "utf8",
  });

  if (result.status !== 0) {
    const stderr = result.stderr?.trim();
    throw new Error(stderr && stderr.length > 0 ? stderr : `git clone failed for ${source}`);
  }

  cleanupTempDir(join(destination, ".git"));
}

export function stageLocalFile(absolutePath: string): ResolvedScanTarget {
  const tempRoot = mkdtempSync(join(tmpdir(), "codegate-scan-target-"));
  if (shouldStageContainingFolder(absolutePath)) {
    const relativeRoot = preserveTailSegments(dirname(absolutePath), 2);
    const destinationDir = join(tempRoot, relativeRoot);
    copyDirectoryRecursive(dirname(absolutePath), destinationDir);

    return {
      scanTarget: tempRoot,
      displayTarget: absolutePath,
      explicitCandidates: collectExplicitCandidates(tempRoot),
      cleanup: () => cleanupTempDir(tempRoot),
    };
  }

  const relativePath = inferLocalFileStagePath(absolutePath);
  const stagedPath = join(tempRoot, relativePath);
  mkdirSync(dirname(stagedPath), { recursive: true });
  copyFileSync(absolutePath, stagedPath);

  return {
    scanTarget: tempRoot,
    displayTarget: absolutePath,
    explicitCandidates: collectExplicitCandidates(tempRoot),
    cleanup: () => cleanupTempDir(tempRoot),
  };
}

export function cloneGitRepo(rawTarget: string): ResolvedScanTarget {
  const tempRoot = mkdtempSync(join(tmpdir(), "codegate-scan-repo-"));
  const repoDir = join(tempRoot, "repo");

  try {
    cloneRepository(rawTarget, repoDir);
  } catch (error) {
    cleanupTempDir(tempRoot);
    throw error;
  }

  return {
    scanTarget: repoDir,
    displayTarget: rawTarget,
    cleanup: () => cleanupTempDir(tempRoot),
  };
}

export function stageRepoSubdirectory(repoUrl: string, filePath: string, displayTarget: string): ResolvedScanTarget {
  const tempRoot = mkdtempSync(join(tmpdir(), "codegate-scan-repo-file-"));
  const repoDir = join(tempRoot, "repo");

  try {
    cloneRepository(repoUrl, repoDir);

    const absoluteFile = join(repoDir, filePath);
    if (!existsSync(absoluteFile)) {
      throw new Error(`Resolved repository file not found after clone: ${filePath}`);
    }

    const stageRoot = join(tempRoot, "staged");
    const relativeRoot = preserveTailSegments(dirname(filePath), 2);
    const destinationDir = join(stageRoot, relativeRoot);
    copyDirectoryRecursive(dirname(absoluteFile), destinationDir);

    return {
      scanTarget: stageRoot,
      displayTarget,
      explicitCandidates: collectExplicitCandidates(stageRoot),
      cleanup: () => cleanupTempDir(tempRoot),
    };
  } catch (error) {
    cleanupTempDir(tempRoot);
    throw error;
  }
}

export async function downloadRemoteFile(rawTarget: string): Promise<ResolvedScanTarget> {
  const githubFile = parseGitHubFileSource(rawTarget);
  if (githubFile && shouldStageContainingFolder(githubFile.filePath)) {
    return stageRepoSubdirectory(githubFile.repoUrl, githubFile.filePath, rawTarget);
  }

  const response = await fetch(rawTarget);
  if (!response.ok) {
    throw new Error(`Failed to download scan target: ${response.status} ${response.statusText}`);
  }

  const content = new Uint8Array(await response.arrayBuffer());
  const tempRoot = mkdtempSync(join(tmpdir(), "codegate-scan-download-"));
  const url = new URL(rawTarget);
  const relativePath = inferRemoteFileStagePath(url);
  const stagedPath = join(tempRoot, relativePath);
  mkdirSync(dirname(stagedPath), { recursive: true });
  writeFileSync(stagedPath, content);

  return {
    scanTarget: tempRoot,
    displayTarget: rawTarget,
    explicitCandidates: collectExplicitCandidates(tempRoot),
    cleanup: () => cleanupTempDir(tempRoot),
  };
}
