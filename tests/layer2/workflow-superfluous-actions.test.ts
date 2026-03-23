import { describe, expect, it } from "vitest";
import { detectWorkflowSuperfluousActions } from "../../src/layer2-static/detectors/workflow-superfluous-actions";

describe("workflow superfluous actions detector", () => {
  it("flags duplicate external action usage within the same job", () => {
    const findings = detectWorkflowSuperfluousActions({
      filePath: ".github/workflows/ci.yml",
      textContent: `on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@v4\n`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            "runs-on": "ubuntu-latest",
            steps: [{ uses: "actions/checkout@v4" }, { uses: "actions/checkout@v4" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-superfluous-actions");
  });

  it("does not flag single-use actions", () => {
    const findings = detectWorkflowSuperfluousActions({
      filePath: ".github/workflows/ci.yml",
      textContent: `on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            "runs-on": "ubuntu-latest",
            steps: [{ uses: "actions/checkout@v4" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
