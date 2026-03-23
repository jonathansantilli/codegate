import { describe, expect, it } from "vitest";
import { detectWorkflowSecretsInherit } from "../../src/layer2-static/detectors/workflow-secrets-inherit";

describe("workflow secrets inherit detector", () => {
  it("flags reusable workflow calls that inherit all secrets", () => {
    const findings = detectWorkflowSecretsInherit({
      filePath: ".github/workflows/reusable.yml",
      textContent: [
        "jobs:",
        "  call-reusable:",
        "    uses: ./.github/workflows/called.yml",
        "    secrets: inherit",
        "",
      ].join("\n"),
      parsed: {
        on: ["workflow_dispatch"],
        jobs: {
          "call-reusable": {
            uses: "./.github/workflows/called.yml",
            secrets: "inherit",
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-secrets-inherit");
    expect(findings[0]?.evidence).toContain("secrets: inherit");
  });

  it("ignores explicit secret forwarding", () => {
    const findings = detectWorkflowSecretsInherit({
      filePath: ".github/workflows/reusable.yml",
      textContent: [
        "jobs:",
        "  call-reusable:",
        "    uses: ./.github/workflows/called.yml",
        "    secrets:",
        "      token: ${{ secrets.TOKEN }}",
        "",
      ].join("\n"),
      parsed: {
        on: ["workflow_dispatch"],
        jobs: {
          "call-reusable": {
            uses: "./.github/workflows/called.yml",
            secrets: {
              token: "${{ secrets.TOKEN }}",
            },
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
