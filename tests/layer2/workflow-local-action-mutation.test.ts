import { describe, expect, it } from "vitest";
import { detectWorkflowLocalActionMutation } from "../../src/layer2-static/detectors/workflow-local-action-mutation";

describe("workflow local action mutation detector", () => {
  it("flags local action usage in untrusted privileged workflow context", () => {
    const findings = detectWorkflowLocalActionMutation({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request_target]
jobs:
  release:
    permissions:
      contents: write
    steps:
      - uses: ./.github/actions/release
`,
      parsed: {
        on: ["pull_request_target"],
        jobs: {
          release: {
            permissions: {
              contents: "write",
            },
            steps: [
              {
                uses: "./.github/actions/release",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-local-action-mutation");
    expect(findings[0]?.severity).toBe("HIGH");
  });

  it("does not flag local action usage on trusted triggers", () => {
    const findings = detectWorkflowLocalActionMutation({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [push]
jobs:
  release:
    permissions:
      contents: write
    steps:
      - uses: ./.github/actions/release
`,
      parsed: {
        on: ["push"],
        jobs: {
          release: {
            permissions: {
              contents: "write",
            },
            steps: [
              {
                uses: "./.github/actions/release",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
