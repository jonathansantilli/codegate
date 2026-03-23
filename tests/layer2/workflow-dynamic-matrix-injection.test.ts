import { describe, expect, it } from "vitest";
import { detectWorkflowDynamicMatrixInjection } from "../../src/layer2-static/detectors/workflow-dynamic-matrix-injection";

describe("workflow dynamic matrix injection detector", () => {
  it("flags dynamic matrix from untrusted event data that flows into shell execution", () => {
    const findings = detectWorkflowDynamicMatrixInjection({
      filePath: ".github/workflows/ci.yml",
      textContent: `on: [pull_request]
jobs:
  build:
    strategy:
      matrix: \${{ fromJSON(github.event.pull_request.title) }}
    steps:
      - run: echo "\${{ matrix.command }}"
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            strategy: {
              matrix: "${{ fromJSON(github.event.pull_request.title) }}",
            },
            steps: [
              {
                run: 'echo "${{ matrix.command }}"',
              },
            ],
          },
        },
      },
    });

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.rule_id).toBe("workflow-dynamic-matrix-injection");
    expect(findings.some((finding) => finding.location.field?.includes("strategy.matrix"))).toBe(
      true,
    );
  });

  it("does not flag static matrix expressions", () => {
    const findings = detectWorkflowDynamicMatrixInjection({
      filePath: ".github/workflows/ci.yml",
      textContent: `on: [pull_request]
jobs:
  build:
    strategy:
      matrix: \${{ fromJSON('{"include":[{"command":"npm test"}]}') }}
    steps:
      - run: echo "\${{ matrix.command }}"
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            strategy: {
              matrix: '${{ fromJSON(\'{"include":[{"command":"npm test"}]}\') }}',
            },
            steps: [
              {
                run: 'echo "${{ matrix.command }}"',
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
