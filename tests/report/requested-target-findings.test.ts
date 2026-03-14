import { describe, expect, it } from "vitest";
import {
  partitionRequestedTargetFindings,
  reorderRequestedTargetFindings,
} from "../../src/report/requested-target-findings";
import type { CodeGateReport } from "../../src/types/report";

function baseReport(findings: CodeGateReport["findings"]): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: "https://github.com/example/repo",
    timestamp: "2026-03-14T00:00:00.000Z",
    kb_version: "2026-03-14",
    tools_detected: ["codex-cli"],
    findings,
    summary: {
      total: findings.length,
      by_severity: {
        CRITICAL: findings.filter((finding) => finding.severity === "CRITICAL").length,
        HIGH: findings.filter((finding) => finding.severity === "HIGH").length,
        MEDIUM: findings.filter((finding) => finding.severity === "MEDIUM").length,
        LOW: findings.filter((finding) => finding.severity === "LOW").length,
        INFO: findings.filter((finding) => finding.severity === "INFO").length,
      },
      fixable: findings.filter((finding) => finding.fixable).length,
      suppressed: findings.filter((finding) => finding.suppressed).length,
      exit_code: findings.some((finding) => finding.severity === "CRITICAL") ? 2 : 1,
    },
  };
}

describe("requested target finding partitioning", () => {
  it("separates URL-target findings from local user-scope and absolute host paths", () => {
    const report = baseReport([
      {
        rule_id: "plugin-manifest-local-source",
        finding_id: "TARGET-1",
        severity: "HIGH",
        category: "RULE_INJECTION",
        layer: "L2",
        file_path: ".claude-plugin/marketplace.json",
        location: { line: 13 },
        description: "Plugin source points to local path: ./",
        affected_tools: ["claude-code"],
        cve: null,
        owasp: ["ASI01"],
        cwe: "CWE-116",
        confidence: "HIGH",
        fixable: true,
        remediation_actions: ["remove_field"],
        suppressed: false,
      },
      {
        rule_id: "rule-file-remote-shell",
        finding_id: "LOCAL-1",
        severity: "CRITICAL",
        category: "RULE_INJECTION",
        layer: "L2",
        file_path: "~/.codex/skills/demo/SKILL.md",
        location: { line: 40 },
        description: "Rule file instructs curl | sh",
        affected_tools: ["codex-cli"],
        cve: null,
        owasp: ["ASI01"],
        cwe: "CWE-116",
        confidence: "HIGH",
        fixable: true,
        remediation_actions: ["remove_block"],
        suppressed: false,
      },
      {
        rule_id: "rule-file-remote-shell",
        finding_id: "LOCAL-2",
        severity: "HIGH",
        category: "RULE_INJECTION",
        layer: "L2",
        file_path: "/Users/demo/.codex/skills/demo/SKILL.md",
        location: { line: 22 },
        description: "Absolute local host file finding",
        affected_tools: ["codex-cli"],
        cve: null,
        owasp: ["ASI01"],
        cwe: "CWE-116",
        confidence: "HIGH",
        fixable: true,
        remediation_actions: ["remove_block"],
        suppressed: false,
      },
    ]);

    const groups = partitionRequestedTargetFindings(report);
    expect(groups).not.toBeNull();
    expect(groups?.targetFindings.map((item) => item.finding_id)).toEqual(["TARGET-1"]);
    expect(groups?.localFindings.map((item) => item.finding_id)).toEqual(["LOCAL-1", "LOCAL-2"]);
  });

  it("reorders findings so requested URL target findings are listed first", () => {
    const report = baseReport([
      {
        rule_id: "rule-file-remote-shell",
        finding_id: "LOCAL-1",
        severity: "CRITICAL",
        category: "RULE_INJECTION",
        layer: "L2",
        file_path: "~/.codex/skills/demo/SKILL.md",
        location: { line: 40 },
        description: "Rule file instructs curl | sh",
        affected_tools: ["codex-cli"],
        cve: null,
        owasp: ["ASI01"],
        cwe: "CWE-116",
        confidence: "HIGH",
        fixable: true,
        remediation_actions: ["remove_block"],
        suppressed: false,
      },
      {
        rule_id: "plugin-manifest-local-source",
        finding_id: "TARGET-1",
        severity: "HIGH",
        category: "RULE_INJECTION",
        layer: "L2",
        file_path: ".claude-plugin/marketplace.json",
        location: { line: 13 },
        description: "Plugin source points to local path: ./",
        affected_tools: ["claude-code"],
        cve: null,
        owasp: ["ASI01"],
        cwe: "CWE-116",
        confidence: "HIGH",
        fixable: true,
        remediation_actions: ["remove_field"],
        suppressed: false,
      },
    ]);

    const ordered = reorderRequestedTargetFindings(report);
    expect(ordered.findings.map((item) => item.finding_id)).toEqual(["TARGET-1", "LOCAL-1"]);
  });
});
