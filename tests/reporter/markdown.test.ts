import { describe, expect, it } from "vitest";
import { renderMarkdownReport } from "../../src/reporter/markdown";
import type { CodeGateReport } from "../../src/types/report";

describe("task 15 markdown reporter", () => {
  it("renders markdown summary and finding rows", () => {
    const report: CodeGateReport = {
      version: "0.1.0",
      scan_target: ".",
      timestamp: "2026-02-28T00:00:00.000Z",
      kb_version: "2026-02-28",
      tools_detected: ["claude-code"],
      findings: [
        {
          rule_id: "env-base-url-override",
          finding_id: "ENV_OVERRIDE-.claude/settings.json-env.ANTHROPIC_BASE_URL",
          fingerprint: "sha256:test",
          severity: "CRITICAL",
          category: "ENV_OVERRIDE",
          layer: "L2",
          file_path: ".claude/settings.json",
          location: { field: "env.ANTHROPIC_BASE_URL", line: 2 },
          description: "Untrusted endpoint",
          affected_tools: ["claude-code"],
          cve: "CVE-2026-21852",
          owasp: ["ASI03"],
          cwe: "CWE-522",
          confidence: "HIGH",
          fixable: true,
          remediation_actions: ["remove_field"],
          metadata: {
            sources: [".claude/settings.json", "env.ANTHROPIC_BASE_URL"],
            sinks: ["api-redirect"],
            referenced_secrets: ["ANTHROPIC_BASE_URL"],
            risk_tags: ["endpoint-override"],
            origin: "markdown-reporter-test",
          },
          suppressed: false,
        },
      ],
      summary: {
        total: 1,
        by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        fixable: 1,
        suppressed: 0,
        exit_code: 2,
      },
    };

    const markdown = renderMarkdownReport(report);
    expect(markdown).toContain("# CodeGate Report");
    expect(markdown).toContain("| CRITICAL | ENV_OVERRIDE");
    expect(markdown).toContain("`.claude/settings.json`");
    expect(markdown).toContain("sha256:test");
    expect(markdown).toContain("sources=.claude/settings.json, env.ANTHROPIC_BASE_URL");
  });
});
