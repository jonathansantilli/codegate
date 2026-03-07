import type { Finding } from "./types/finding.js";
import type { CodeGateReport, ReportSummary } from "./types/report.js";

export type ReportThreshold = "critical" | "high" | "medium" | "low" | "info";

const SEVERITY_LEVEL: Record<Finding["severity"], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

const THRESHOLD_LEVEL: Record<ReportThreshold, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function computeExitCode(findings: Finding[], threshold: ReportThreshold = "high"): number {
  const unsuppressed = findings.filter((finding) => !finding.suppressed);
  if (unsuppressed.length === 0) {
    return 0;
  }

  const thresholdLevel = THRESHOLD_LEVEL[threshold];
  const hasDangerous = unsuppressed.some(
    (finding) => SEVERITY_LEVEL[finding.severity] >= thresholdLevel,
  );
  return hasDangerous ? 2 : 1;
}

export function summarizeFindings(
  findings: Finding[],
  threshold: ReportThreshold = "high",
): ReportSummary {
  const bySeverity: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
  }

  return {
    total: findings.length,
    by_severity: bySeverity,
    fixable: findings.filter((finding) => finding.fixable).length,
    suppressed: findings.filter((finding) => finding.suppressed).length,
    exit_code: computeExitCode(findings, threshold),
  };
}

export function applyReportSummary(
  report: CodeGateReport,
  threshold: ReportThreshold = "high",
): CodeGateReport {
  return {
    ...report,
    summary: summarizeFindings(report.findings, threshold),
  };
}
