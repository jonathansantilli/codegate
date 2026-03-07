import { describe, expect, it } from "vitest";
import { evaluatePostScanGuard, evaluatePreLaunchGuard } from "../../src/commands/run-policy";
import type { CodeGateReport } from "../../src/types/report";
import type { Finding } from "../../src/types/finding";

function report(exitCode: number, total = exitCode === 0 ? 0 : 1): CodeGateReport {
  const findings: Finding[] =
    total > 0
      ? [
          {
            rule_id: "test-rule",
            finding_id: `TEST-${exitCode}`,
            severity: exitCode === 2 ? "HIGH" : "LOW",
            category: "COMMAND_EXEC",
            layer: "L2",
            file_path: ".mcp.json",
            location: { field: "mcpServers.bad.command" },
            description: "test finding",
            affected_tools: ["claude-code"],
            cve: null,
            owasp: ["ASI05"],
            cwe: "CWE-78",
            confidence: "HIGH",
            fixable: true,
            remediation_actions: ["remove_field"],
            suppressed: false,
          },
        ]
      : [];

  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-03-06T00:00:00.000Z",
    kb_version: "2026-03-06",
    tools_detected: ["claude-code"],
    findings,
    summary: {
      total,
      by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      fixable: 0,
      suppressed: 0,
      exit_code: exitCode,
    },
  };
}

describe("run policy", () => {
  it("blocks dangerous findings immediately", () => {
    expect(
      evaluatePostScanGuard({
        report: report(2),
        scanSurfaceChanged: false,
        force: false,
        autoProceedBelowThreshold: true,
        insideTrustedDirectory: false,
      }),
    ).toEqual({
      kind: "block",
      exitCode: 2,
      message: "Dangerous findings detected. Resolve issues before launching tool.",
      stream: "stderr",
    });
  });

  it("requires confirmation for warning findings when no bypass applies", () => {
    expect(
      evaluatePostScanGuard({
        report: report(1),
        scanSurfaceChanged: false,
        force: false,
        autoProceedBelowThreshold: false,
        insideTrustedDirectory: false,
      }),
    ).toEqual({ kind: "prompt" });
  });

  it("blocks when config files change after scan", () => {
    expect(
      evaluatePostScanGuard({
        report: report(0),
        scanSurfaceChanged: true,
        force: false,
        autoProceedBelowThreshold: true,
        insideTrustedDirectory: false,
      }),
    ).toEqual({
      kind: "block",
      exitCode: 3,
      message: "Config files changed after scan. Re-run `codegate scan` before launch.",
      stream: "stderr",
    });
  });

  it("blocks before launch when the pre-launch snapshot changed", () => {
    expect(evaluatePreLaunchGuard({ launchSurfaceChanged: true })).toEqual({
      kind: "block",
      exitCode: 3,
      message: "Config files changed after scan. Re-run `codegate scan` before launch.",
      stream: "stderr",
    });
  });

  it("allows launch when nothing blocks or prompts", () => {
    expect(
      evaluatePostScanGuard({
        report: report(1),
        scanSurfaceChanged: false,
        force: true,
        autoProceedBelowThreshold: false,
        insideTrustedDirectory: false,
      }),
    ).toEqual({ kind: "allow" });
    expect(evaluatePreLaunchGuard({ launchSurfaceChanged: false })).toEqual({ kind: "allow" });
  });
});
