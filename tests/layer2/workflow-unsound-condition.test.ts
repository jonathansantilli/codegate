import { describe, expect, it } from "vitest";
import { detectWorkflowUnsoundCondition } from "../../src/layer2-static/detectors/workflow-unsound-condition";

describe("workflow unsound condition detector", () => {
  it("flags always() conditions on sensitive execution steps", () => {
    const findings = detectWorkflowUnsoundCondition({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [push]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - if: always()\n        run: npm publish\n`,
      parsed: {
        on: ["push"],
        jobs: {
          publish: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                if: "always()",
                run: "npm publish",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-unsound-condition");
  });

  it("does not flag bounded conditions", () => {
    const findings = detectWorkflowUnsoundCondition({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [push]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - if: success()\n        run: npm publish\n`,
      parsed: {
        on: ["push"],
        jobs: {
          publish: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                if: "success()",
                run: "npm publish",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
