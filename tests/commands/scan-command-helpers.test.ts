import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  noEligibleDeepResourceNotes,
  parseLocalTextFindings,
  parseMetaAgentOutput,
  remediationSummaryLines,
  summarizeRequestedTargetFindings,
} from "../../src/commands/scan-command/helpers";
import type { ScanCommandOptions } from "../../src/commands/scan-command";
import type { CodeGateReport } from "../../src/types/report";
import { normalizeLines } from "../helpers/path";

function emptyReport(): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-03-07T00:00:00.000Z",
    kb_version: "2026-03-07",
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
}

describe("scan command helpers", () => {
  it("parses meta-agent JSON envelopes and fenced JSON", () => {
    expect(parseMetaAgentOutput('{"result":"{\\"findings\\":[{\\"id\\":\\"L3-1\\"}]}"}')).toEqual({
      findings: [{ id: "L3-1" }],
    });

    expect(parseMetaAgentOutput('```json\n{"findings":[{"id":"L3-2"}]}\n```')).toEqual({
      findings: [{ id: "L3-2" }],
    });
  });

  it("normalizes local text analysis findings into report findings", () => {
    expect(
      parseLocalTextFindings("skills/demo/SKILL.md", {
        findings: [
          {
            id: "L3-local-1",
            severity: "HIGH",
            category: "RULE_INJECTION",
            description: "Hidden payload detected",
            field: "content",
            evidence: "<!-- hidden -->",
            owasp: ["ASI01"],
          },
        ],
      }),
    ).toEqual([
      expect.objectContaining({
        rule_id: "L3-local-1",
        finding_id: "L3-local-1",
        severity: "HIGH",
        category: "RULE_INJECTION",
        file_path: "skills/demo/SKILL.md",
        evidence: "<!-- hidden -->",
      }),
    ]);
  });

  it("formats remediation summary lines with backup and action details", () => {
    const scanTarget = "/tmp/codegate-demo";
    const result = remediationSummaryLines({
      scanTarget,
      options: { remediate: true } satisfies ScanCommandOptions,
      before: {
        ...emptyReport(),
        summary: {
          ...emptyReport().summary,
          total: 3,
        },
      },
      result: {
        report: {
          ...emptyReport(),
          summary: {
            ...emptyReport().summary,
            total: 1,
          },
        },
        plannedCount: 2,
        appliedCount: 1,
        backupSessionId: "session-123",
        appliedActions: [
          {
            findingId: "F-1",
            action: "remove_field",
            filePath: ".mcp.json",
          },
        ],
      },
    });
    const normalized = normalizeLines(result);

    expect(normalized).toContain("Remediation summary:");
    expect(normalized).toContain("Mode: remediate");
    expect(normalized).toContain("Findings before remediation: 3");
    expect(normalized).toContain("Findings after remediation: 1");
    expect(normalized).toContain(
      `Backup session: ${resolve(scanTarget, ".codegate-backup", "session-123").replaceAll("\\", "/")}`,
    );
    expect(normalized).toContain(
      `- remove_field -> ${resolve(scanTarget, ".mcp.json").replaceAll("\\", "/")} (F-1)`,
    );
  });

  it("returns the stock no-resource deep scan notes", () => {
    expect(noEligibleDeepResourceNotes()).toEqual([
      "Deep scan skipped: no eligible external resources were discovered.",
      "Deep scan analyzes only remote MCP URLs (http/sse) and package-backed commands (npx/uvx/pipx).",
      "Local stdio commands (for example `bash`) are still detected by Layer 2 but are never executed by deep scan.",
    ]);
  });

  it("summarizes URL target findings when only user-scope files triggered findings", () => {
    const report: CodeGateReport = {
      ...emptyReport(),
      findings: [
        {
          rule_id: "rule-file-remote-shell",
          finding_id: "RULE-1",
          severity: "CRITICAL",
          category: "RULE_INJECTION",
          layer: "L2",
          file_path: "~/.codex/skills/demo/SKILL.md",
          location: { field: "remote_shell", line: 12, column: 3 },
          description: "Remote shell pattern",
          affected_tools: ["codex-cli"],
          cve: null,
          owasp: ["ASI01"],
          cwe: "CWE-116",
          confidence: "HIGH",
          fixable: true,
          remediation_actions: ["remove_block"],
          suppressed: false,
        },
      ],
      summary: {
        ...emptyReport().summary,
        total: 1,
        by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        fixable: 1,
        exit_code: 2,
      },
    };

    expect(
      summarizeRequestedTargetFindings(
        report,
        "https://github.com/affaan-m/everything-claude-code/tree/main/skills/agentic-engineering",
      ),
    ).toContain("Requested URL target result: no findings were detected in the URL content");
  });

  it("returns null for non-URL targets", () => {
    expect(summarizeRequestedTargetFindings(emptyReport(), "/tmp/project")).toBeNull();
  });
});
