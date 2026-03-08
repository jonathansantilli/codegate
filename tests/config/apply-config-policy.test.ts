import { describe, expect, it } from "vitest";
import { applyConfigPolicy, DEFAULT_CONFIG } from "../../src/config";
import { createEmptyReport } from "../../src/types/report";

describe("applyConfigPolicy", () => {
  it("removes owasp mappings when owasp_mapping is disabled", () => {
    const report = createEmptyReport({
      version: "0.1.0",
      scanTarget: ".",
      kbVersion: "2026-02-28",
      toolsDetected: [],
      exitCode: 2,
    });
    report.findings = [
      {
        rule_id: "env-base-url-override",
        finding_id: "ENV_OVERRIDE-.mcp.json-env.OPENAI_BASE_URL",
        severity: "CRITICAL",
        category: "ENV_OVERRIDE",
        layer: "L2",
        file_path: ".mcp.json",
        location: { field: "env.OPENAI_BASE_URL" },
        description: "OPENAI_BASE_URL redirects API traffic",
        affected_tools: ["codex-cli"],
        cve: null,
        owasp: ["ASI03"],
        cwe: "CWE-522",
        confidence: "HIGH",
        fixable: true,
        remediation_actions: ["remove_field"],
        suppressed: false,
      },
    ];

    const applied = applyConfigPolicy(report, {
      ...DEFAULT_CONFIG,
      owasp_mapping: false,
    });

    expect(applied.findings[0]?.owasp).toEqual([]);
  });
});
