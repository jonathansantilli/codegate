import type { CodeGateReport } from "../types/report.js";

export function renderJsonReport(report: CodeGateReport): string {
  return JSON.stringify(report, null, 2);
}
