import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  cleanupTempDir,
  collectExplicitCandidates,
  copyDirectoryRecursive,
  extractSkillFromRepoPath,
  inferRemoteCandidateFormat,
  inferLocalFileStagePath,
  inferRemoteFileStagePath,
  inferToolFromReportPath,
  parseGitHubFileSource,
  preserveTailSegments,
  shouldStageContainingFolder,
} from "./helpers.js";
import type { ExplicitScanCandidate, ResolvedScanTarget } from "./types.js";

interface CloneGitRepoOptions {
  preferredSkill?: string;
  inferredSkill?: string;
  interactive?: boolean;
  requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
  displayTarget?: string;
}

function cloneRepository(source: string, destination: string): void {
  const result = spawnSync(
    "git",
    ["clone", "--depth", "1", "--filter=blob:none", source, destination],
    {
      encoding: "utf8",
    },
  );

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

function listAvailableSkills(repoDir: string): string[] {
  const skillsRoot = join(repoDir, "skills");
  if (!existsSync(skillsRoot)) {
    return [];
  }
  try {
    if (!statSync(skillsRoot).isDirectory()) {
      return [];
    }
  } catch {
    return [];
  }

  const skills = readdirSync(skillsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => existsSync(join(skillsRoot, name, "SKILL.md")))
    .sort((left, right) => left.localeCompare(right));

  return skills;
}

function copyRootScanSurface(repoDir: string, stageRoot: string): void {
  for (const entry of readdirSync(repoDir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "skills") {
      continue;
    }

    const sourcePath = join(repoDir, entry.name);
    const destinationPath = join(stageRoot, entry.name);

    if (entry.isFile()) {
      mkdirSync(stageRoot, { recursive: true });
      copyFileSync(sourcePath, destinationPath);
      continue;
    }

    if (entry.isDirectory() && (entry.name.startsWith(".") || entry.name === "hooks")) {
      copyDirectoryRecursive(sourcePath, destinationPath);
    }
  }
}

function normalizeSkillName(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) {
    return null;
  }
  return trimmed.replace(/^skills\//iu, "").replace(/^\/+/u, "");
}

function pickSkill(
  availableSkills: string[],
  preferredSkill: string | undefined,
  inferredSkill: string | undefined,
): string | null {
  const normalizedPreferred = normalizeSkillName(preferredSkill);
  if (normalizedPreferred) {
    return normalizedPreferred;
  }
  const normalizedInferred = normalizeSkillName(inferredSkill);
  if (normalizedInferred) {
    return normalizedInferred;
  }
  if (availableSkills.length === 1) {
    return availableSkills[0] ?? null;
  }
  return null;
}

async function stageSkillAwareRepository(
  tempRoot: string,
  repoDir: string,
  displayTarget: string,
  options: CloneGitRepoOptions = {},
): Promise<ResolvedScanTarget> {
  const availableSkills = listAvailableSkills(repoDir);
  if (availableSkills.length === 0) {
    return {
      scanTarget: repoDir,
      displayTarget,
      cleanup: () => cleanupTempDir(tempRoot),
    };
  }

  let selectedSkill = pickSkill(availableSkills, options.preferredSkill, options.inferredSkill);
  if (
    !selectedSkill &&
    options.interactive === true &&
    options.requestSkillSelection &&
    availableSkills.length > 1
  ) {
    const choice = await options.requestSkillSelection(availableSkills);
    selectedSkill = normalizeSkillName(choice ?? undefined);
  }

  if (!selectedSkill) {
    throw new Error(
      `Multiple skills detected (${availableSkills.join(", ")}). Re-run with --skill <name>.`,
    );
  }

  if (!availableSkills.includes(selectedSkill)) {
    throw new Error(
      `Requested skill "${selectedSkill}" was not found. Available skills: ${availableSkills.join(", ")}.`,
    );
  }

  const stageRoot = join(tempRoot, "staged");
  copyRootScanSurface(repoDir, stageRoot);
  copyDirectoryRecursive(
    join(repoDir, "skills", selectedSkill),
    join(stageRoot, "skills", selectedSkill),
  );

  return {
    scanTarget: stageRoot,
    displayTarget,
    explicitCandidates: collectExplicitCandidates(stageRoot),
    cleanup: () => cleanupTempDir(tempRoot),
  };
}

export async function cloneGitRepo(
  rawTarget: string,
  options: CloneGitRepoOptions = {},
): Promise<ResolvedScanTarget> {
  const tempRoot = mkdtempSync(join(tmpdir(), "codegate-scan-repo-"));
  const repoDir = join(tempRoot, "repo");

  try {
    cloneRepository(rawTarget, repoDir);
    return await stageSkillAwareRepository(
      tempRoot,
      repoDir,
      options.displayTarget ?? rawTarget,
      options,
    );
  } catch (error) {
    cleanupTempDir(tempRoot);
    throw error;
  }
}

export function stageRepoSubdirectory(
  repoUrl: string,
  filePath: string,
  displayTarget: string,
): ResolvedScanTarget {
  const tempRoot = mkdtempSync(join(tmpdir(), "codegate-scan-repo-file-"));
  const repoDir = join(tempRoot, "repo");

  try {
    cloneRepository(repoUrl, repoDir);

    const inferredSkill = extractSkillFromRepoPath(filePath);
    if (inferredSkill) {
      const stageRoot = join(tempRoot, "staged");
      copyRootScanSurface(repoDir, stageRoot);
      copyDirectoryRecursive(
        join(repoDir, "skills", inferredSkill),
        join(stageRoot, "skills", inferredSkill),
      );
      return {
        scanTarget: stageRoot,
        displayTarget,
        explicitCandidates: collectExplicitCandidates(stageRoot),
        cleanup: () => cleanupTempDir(tempRoot),
      };
    }

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

  const tempRoot = mkdtempSync(join(tmpdir(), "codegate-scan-download-"));
  const url = new URL(rawTarget);
  const relativePath = inferRemoteFileStagePath(url);
  const textContent = await response.text();
  const format = inferRemoteCandidateFormat(relativePath, response.headers.get("content-type"));
  if (!format) {
    cleanupTempDir(tempRoot);
    throw new Error(`Unsupported remote scan target format for ${rawTarget}`);
  }

  // Keep direct remote file contents in memory so untrusted downloads are analyzed without
  // persisting arbitrary response bytes to disk.
  const explicitCandidate: ExplicitScanCandidate = {
    reportPath: relativePath,
    absolutePath: join(tempRoot, relativePath),
    format,
    tool: inferToolFromReportPath(relativePath),
    textContent,
  };

  return {
    scanTarget: tempRoot,
    displayTarget: rawTarget,
    explicitCandidates: [explicitCandidate],
    cleanup: () => cleanupTempDir(tempRoot),
  };
}
