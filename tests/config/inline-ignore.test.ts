import { describe, expect, it } from "vitest";
import {
  applyInlineIgnoreDirectives,
  collectInlineIgnoreDirectives,
} from "../../src/config/inline-ignore";
import type { Finding } from "../../src/types/finding";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    rule_id: "workflow-unpinned-uses",
    finding_id: "WORKFLOW_UNPINNED_USES-.github/workflows/ci.yml-0-0",
    severity: "HIGH",
    category: "CI_SUPPLY_CHAIN",
    layer: "L2",
    file_path: ".github/workflows/ci.yml",
    location: { field: "jobs.test.steps[0].uses", line: 2, column: 3 },
    description: "test",
    affected_tools: ["github-actions"],
    cve: null,
    owasp: ["ASI02"],
    cwe: "CWE-829",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    suppressed: false,
    ...overrides,
  };
}

describe("inline ignore directives", () => {
  it("collects yaml and markdown ignore directives", () => {
    const directives = collectInlineIgnoreDirectives([
      {
        filePath: ".github/workflows/ci.yml",
        textContent: "# codegate: ignore[workflow-unpinned-uses]",
      },
      {
        filePath: "skills/security-review/SKILL.md",
        textContent: "<!-- codegate: ignore[rule-file-remote-shell] -->",
      },
    ]);

    expect(directives.get(".github/workflows/ci.yml")?.rules.has("workflow-unpinned-uses")).toBe(
      true,
    );
    expect(
      directives.get("skills/security-review/SKILL.md")?.rules.has("rule-file-remote-shell"),
    ).toBe(true);
  });

  it("suppresses findings when an inline ignore matches rule and file", () => {
    const directives = collectInlineIgnoreDirectives([
      {
        filePath: ".github/workflows/ci.yml",
        textContent: "# codegate: ignore[workflow-unpinned-uses]",
      },
    ]);

    const [suppressed, active] = applyInlineIgnoreDirectives(
      [
        makeFinding(),
        makeFinding({
          rule_id: "workflow-dangerous-triggers",
          finding_id: "WORKFLOW_DANGEROUS_TRIGGERS-.github/workflows/ci.yml",
        }),
      ],
      directives,
    );

    expect(suppressed?.suppressed).toBe(true);
    expect(active?.suppressed).toBe(false);
  });
});
