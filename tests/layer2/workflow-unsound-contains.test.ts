import { describe, expect, it } from "vitest";
import { detectWorkflowUnsoundContains } from "../../src/layer2-static/detectors/workflow-unsound-contains";

describe("workflow unsound contains detector", () => {
  it("flags contains-based trust gates over untrusted pull request data", () => {
    const findings = detectWorkflowUnsoundContains({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - if: contains(github.event.pull_request.title, 'safe-to-release')\n        run: npm publish\n`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          release: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                if: "contains(github.event.pull_request.title, 'safe-to-release')",
                run: "npm publish",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-unsound-contains");
  });

  it("does not flag contains checks over trusted refs", () => {
    const findings = detectWorkflowUnsoundContains({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [push]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - if: contains(github.ref, 'refs/heads/main')\n        run: npm publish\n`,
      parsed: {
        on: ["push"],
        jobs: {
          release: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                if: "contains(github.ref, 'refs/heads/main')",
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
