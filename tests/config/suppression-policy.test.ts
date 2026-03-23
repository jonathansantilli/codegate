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

  it("supports coordinate-based suppression matching", () => {
    const [suppressed, active] = applySuppressionPolicy(
      [
        makeFinding({
          location: { field: "env.OPENAI_BASE_URL", line: 42, column: 7 },
        }),
        makeFinding({
          location: { field: "env.OPENAI_BASE_URL", line: 11, column: 3 },
        }),
      ],
      {
        suppress_findings: [],
        suppression_rules: [
          {
            rule_id: "env-base-url-override",
            location: "packages/app/.mcp.json:42:7",
          },
        ],
      },
    );

    expect(suppressed?.suppressed).toBe(true);
    expect(active?.suppressed).toBe(false);
  });

  it("suppresses findings when a rule is disabled or ignored by rule policy", () => {
    const [disabled, ignored, active] = applySuppressionPolicy(
      [
        makeFinding({
          rule_id: "workflow-dangerous-triggers",
          finding_id: "WORKFLOW_DANGEROUS_TRIGGERS-.github/workflows/ci.yml",
          file_path: ".github/workflows/ci.yml",
          location: { field: "on", line: 4, column: 2 },
        }),
        makeFinding({
          rule_id: "workflow-unpinned-uses",
          finding_id: "WORKFLOW_UNPINNED_USES-.github/workflows/ci.yml-0-0",
          file_path: ".github/workflows/ci.yml",
          location: { field: "jobs.build.steps[0].uses", line: 12, column: 7 },
        }),
        makeFinding({
          rule_id: "workflow-unpinned-uses",
          finding_id: "WORKFLOW_UNPINNED_USES-.github/workflows/ci.yml-0-1",
          file_path: ".github/workflows/ci.yml",
          location: { field: "jobs.build.steps[1].uses", line: 18, column: 7 },
        }),
      ],
      {
        suppress_findings: [],
        suppression_rules: [],
        rule_policies: {
          "workflow-dangerous-triggers": { disable: true },
          "workflow-unpinned-uses": {
            ignore: [".github/workflows/ci.yml:12:7"],
          },
        },
      },
    );

    expect(disabled?.suppressed).toBe(true);
    expect(ignored?.suppressed).toBe(true);
    expect(active?.suppressed).toBe(false);
  });
});
