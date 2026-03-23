import { describe, expect, it } from "vitest";
import { detectWorkflowConcurrencyLimits } from "../../src/layer2-static/detectors/workflow-concurrency-limits";

describe("workflow concurrency limits detector", () => {
  it("flags risky-trigger workflows that do not define concurrency", () => {
    const findings = detectWorkflowConcurrencyLimits({
      filePath: ".github/workflows/pr-target.yml",
      textContent: `on:\n  pull_request_target:\n    types: [opened]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo review\n`,
      parsed: {
        on: {
          pull_request_target: {
            types: ["opened"],
          },
        },
        jobs: {
          review: {
            "runs-on": "ubuntu-latest",
            steps: [{ run: "echo review" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-concurrency-limits");
  });

  it("does not flag workflows with top-level concurrency", () => {
    const findings = detectWorkflowConcurrencyLimits({
      filePath: ".github/workflows/pr-target.yml",
      textContent: `on:\n  pull_request_target:\n    types: [opened]\nconcurrency:\n  group: secure-\${{ github.ref }}\n  cancel-in-progress: true\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo review\n`,
      parsed: {
        on: {
          pull_request_target: {
            types: ["opened"],
          },
        },
        concurrency: {
          group: "secure-${{ github.ref }}",
          "cancel-in-progress": true,
        },
        jobs: {
          review: {
            "runs-on": "ubuntu-latest",
            steps: [{ run: "echo review" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
