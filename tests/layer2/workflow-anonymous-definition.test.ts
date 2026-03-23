import { describe, expect, it } from "vitest";
import { detectWorkflowAnonymousDefinition } from "../../src/layer2-static/detectors/workflow-anonymous-definition";

describe("workflow anonymous definition detector", () => {
  it("flags workflows that omit a top-level name", () => {
    const findings = detectWorkflowAnonymousDefinition({
      filePath: ".github/workflows/ci.yml",
      textContent: `on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n`,
      parsed: {
        on: ["push"],
        jobs: {
          test: {
            "runs-on": "ubuntu-latest",
            steps: [{ run: "echo ok" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-anonymous-definition");
  });

  it("does not flag workflows with a top-level name", () => {
    const findings = detectWorkflowAnonymousDefinition({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n`,
      parsed: {
        name: "CI",
        on: ["push"],
        jobs: {
          test: {
            "runs-on": "ubuntu-latest",
            steps: [{ run: "echo ok" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
