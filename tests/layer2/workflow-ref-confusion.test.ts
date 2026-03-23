import { describe, expect, it } from "vitest";
import { detectWorkflowRefConfusion } from "../../src/layer2-static/detectors/workflow-ref-confusion";

describe("workflow ref confusion detector", () => {
  it("flags repository actions pinned to symbolic refs", () => {
    const findings = detectWorkflowRefConfusion({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@v4",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-ref-confusion");
    expect(findings[0]?.evidence).toContain("actions/checkout@v4");
  });

  it("does not flag hash-pinned, local, or docker uses", () => {
    const findings = detectWorkflowRefConfusion({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.20
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@0123456789abcdef0123456789abcdef01234567",
              },
              {
                uses: "./.github/actions/local",
              },
              {
                uses: "docker://alpine:3.20",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
