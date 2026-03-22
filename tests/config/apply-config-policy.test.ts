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
        fingerprint: "sha256:test-fingerprint",
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
    expect(applied.findings[0]?.fingerprint).toBe("sha256:test-fingerprint");
  });

  it("applies suppression rules and recomputes the report summary", () => {
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
        finding_id: "ENV_OVERRIDE-packages/app/.mcp.json-env.OPENAI_BASE_URL",
        fingerprint: "sha256:match",
        severity: "CRITICAL",
        category: "ENV_OVERRIDE",
        layer: "L2",
        file_path: "packages/app/.mcp.json",
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
      {
        rule_id: "local-text-finding",
        finding_id: "ACTIVE-1",
        severity: "LOW",
        category: "CONFIG_PRESENT",
        layer: "L1",
        file_path: "README.md",
        location: { field: "content" },
        description: "test finding",
        affected_tools: ["codex-cli"],
        cve: null,
        owasp: [],
        cwe: "CWE-1036",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [],
        suppressed: false,
      },
    ];

    const applied = applyConfigPolicy(report, {
      ...DEFAULT_CONFIG,
      owasp_mapping: false,
      suppress_findings: ["legacy-suppression"],
      suppression_rules: [
        {
          rule_id: "env-base-url-override",
          file_path: "**/*.mcp.json",
          severity: "CRITICAL",
          category: "ENV_OVERRIDE",
          cwe: "CWE-522",
          fingerprint: "sha256:match",
        },
      ],
    });

    expect(applied.findings[0]?.suppressed).toBe(true);
    expect(applied.findings[0]?.owasp).toEqual([]);
    expect(applied.findings[1]?.suppressed).toBe(false);
    expect(applied.summary).toMatchObject({
      total: 2,
      suppressed: 1,
      exit_code: 1,
    });
  });
});
