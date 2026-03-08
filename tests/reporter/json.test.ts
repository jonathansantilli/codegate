import { describe, expect, it } from "vitest";
import { renderJsonReport } from "../../src/reporter/json";
import type { CodeGateReport } from "../../src/types/report";

describe("task 15 json reporter", () => {
  it("serializes report as pretty JSON", () => {
    const report: CodeGateReport = {
      version: "0.1.0",
      scan_target: ".",
      timestamp: "2026-02-28T00:00:00.000Z",
      kb_version: "2026-02-28",
      tools_detected: ["claude-code"],
      findings: [],
      summary: {
        total: 0,
        by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        fixable: 0,
        suppressed: 0,
        exit_code: 0,
      },
    };

    const json = renderJsonReport(report);
    expect(JSON.parse(json)).toEqual(report);
  });
});
