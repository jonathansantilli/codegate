import { describe, expect, it } from "vitest";
import { applySuppressionPolicy } from "../../src/config/suppression-policy";
import type { Finding } from "../../src/types/finding";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
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
    ...overrides,
  };
}

describe("suppression policy", () => {
  it("suppresses a finding only when every rule criterion matches", () => {
    const policy = {
      suppress_findings: [],
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
    };

    const [matching, wrongSeverity, wrongCategory, wrongFingerprint] = applySuppressionPolicy(
      [
        makeFinding(),
        makeFinding({ severity: "HIGH" }),
        makeFinding({ category: "COMMAND_EXEC" }),
        makeFinding({ fingerprint: "sha256:different" }),
      ],
      policy,
    );

    expect(matching?.suppressed).toBe(true);
    expect(wrongSeverity?.suppressed).toBe(false);
    expect(wrongCategory?.suppressed).toBe(false);
    expect(wrongFingerprint?.suppressed).toBe(false);
  });

  it("keeps suppress_findings backward compatible", () => {
    const [suppressed, active] = applySuppressionPolicy(
      [
        makeFinding({ finding_id: "legacy-suppression" }),
        makeFinding({ finding_id: "active-finding" }),
      ],
      {
        suppress_findings: ["legacy-suppression"],
        suppression_rules: [],
      },
    );

    expect(suppressed?.suppressed).toBe(true);
    expect(active?.suppressed).toBe(false);
  });
});
