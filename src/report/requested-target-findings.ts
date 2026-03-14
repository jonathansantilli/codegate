import { isAbsolute } from "node:path";
import type { Finding } from "../types/finding.js";
import type { CodeGateReport } from "../types/report.js";

const HTTP_LIKE_TARGET_PATTERN = /^https?:\/\//iu;
const WINDOWS_ABSOLUTE_PATH_PATTERN = /^[a-z]:[\\/]/iu;

export interface RequestedTargetFindingGroups {
  targetFindings: Finding[];
  localFindings: Finding[];
}

function isHttpLikeTarget(target: string): boolean {
  return HTTP_LIKE_TARGET_PATTERN.test(target);
}

function isUserScopeFindingPath(path: string): boolean {
  return path === "~" || path.startsWith("~/");
}

function isWindowsAbsolutePath(path: string): boolean {
  return WINDOWS_ABSOLUTE_PATH_PATTERN.test(path);
}

function isLocalHostFindingPath(path: string): boolean {
  return isUserScopeFindingPath(path) || isAbsolute(path) || isWindowsAbsolutePath(path);
}

export function partitionRequestedTargetFindings(
  report: CodeGateReport,
  displayTarget?: string,
): RequestedTargetFindingGroups | null {
  const target = displayTarget ?? report.scan_target;
  if (!isHttpLikeTarget(target)) {
    return null;
  }

  const targetFindings: Finding[] = [];
  const localFindings: Finding[] = [];
  for (const finding of report.findings) {
    if (isLocalHostFindingPath(finding.file_path)) {
      localFindings.push(finding);
      continue;
    }

    targetFindings.push(finding);
  }

  return {
    targetFindings,
    localFindings,
  };
}

export function reorderRequestedTargetFindings(
  report: CodeGateReport,
  displayTarget?: string,
): CodeGateReport {
  const groups = partitionRequestedTargetFindings(report, displayTarget);
  if (!groups) {
    return report;
  }

  return {
    ...report,
    findings: [...groups.targetFindings, ...groups.localFindings],
  };
}
