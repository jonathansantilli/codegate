import type { Finding } from "./finding.js";

export interface ReportSummary {
  total: number;
  by_severity: Record<string, number>;
  fixable: number;
  suppressed: number;
  exit_code: number;
}

export interface CodeGateReport {
  version: string;
  scan_target: string;
  timestamp: string;
  kb_version: string;
  tools_detected: string[];
  findings: Finding[];
  summary: ReportSummary;
}

export interface EmptyReportOptions {
  version: string;
  scanTarget: string;
  kbVersion: string;
  toolsDetected: string[];
  exitCode: number;
}

export function createEmptyReport(options: EmptyReportOptions): CodeGateReport {
  return {
    version: options.version,
    scan_target: options.scanTarget,
    timestamp: new Date().toISOString(),
    kb_version: options.kbVersion,
    tools_detected: options.toolsDetected,
    findings: [],
    summary: {
      total: 0,
      by_severity: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0,
      },
      fixable: 0,
      suppressed: 0,
      exit_code: options.exitCode,
    },
  };
}
