import { describe, expect, it } from "vitest";
import { detectWorkflowArtipacked } from "../../src/layer2-static/detectors/workflow-artipacked";

describe("workflow artipacked detector", () => {
  it("flags checkout steps that keep persisted credentials enabled", () => {
    const findings = detectWorkflowArtipacked({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: true
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@v4",
                with: {
                  "persist-credentials": "true",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-artipacked");
    expect(findings[0]?.evidence).toContain("persist-credentials: true");
  });

  it("ignores checkout steps that disable credential persistence", () => {
    const findings = detectWorkflowArtipacked({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@v4",
                with: {
                  "persist-credentials": "false",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
