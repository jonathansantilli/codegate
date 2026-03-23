import { describe, expect, it } from "vitest";
import { renderSarifReport } from "../../src/reporter/sarif";
import type { CodeGateReport } from "../../src/types/report";

describe("task 15 sarif reporter", () => {
  it("maps findings to SARIF rules and results", () => {
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
          affected_locations: [
            {
              file_path: ".claude/settings.json",
              location: { field: "mcpServers.bad.command", line: 9, column: 3 },
            },
          ],
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
            origin: "sarif-reporter-test",
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

    const sarif = JSON.parse(renderSarifReport(report)) as {
      version: string;
      runs: Array<{
        tool: { driver: { rules: Array<{ id: string }> } };
        results: Array<{
          ruleId: string;
          properties?: Record<string, unknown>;
          relatedLocations?: Array<unknown>;
        }>;
      }>;
    };

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.tool.driver.rules[0]?.id).toBe("env-base-url-override");
    expect(sarif.runs[0]?.results[0]?.ruleId).toBe("env-base-url-override");
    expect(sarif.runs[0]?.results[0]?.properties?.finding_id).toBe(
      "ENV_OVERRIDE-.claude/settings.json-env.ANTHROPIC_BASE_URL",
    );
    expect(sarif.runs[0]?.results[0]?.properties?.fingerprint).toBe("sha256:test");
    expect(sarif.runs[0]?.results[0]?.properties?.metadata).toMatchObject({
      sources: [".claude/settings.json", "env.ANTHROPIC_BASE_URL"],
      sinks: ["api-redirect"],
      origin: "sarif-reporter-test",
    });
    expect(sarif.runs[0]?.results[0]?.relatedLocations?.length).toBe(1);
  });
});
