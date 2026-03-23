import { describe, expect, it } from "vitest";
import { detectWorkflowUnredactedSecrets } from "../../src/layer2-static/detectors/workflow-unredacted-secrets";

describe("workflow unredacted secrets detector", () => {
  it("flags plaintext secret-like env values", () => {
    const findings = detectWorkflowUnredactedSecrets({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [push]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
        env:
          NPM_TOKEN: abc123plaintexttoken
`,
      parsed: {
        on: ["push"],
        jobs: {
          release: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                run: "npm publish",
                env: {
                  NPM_TOKEN: "abc123plaintexttoken",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("unredacted-secrets");
  });

  it("does not flag references to repository secrets", () => {
    const findings = detectWorkflowUnredactedSecrets({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [push]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
        env:
          NPM_TOKEN: \${{ secrets.NPM_TOKEN }}
`,
      parsed: {
        on: ["push"],
        jobs: {
          release: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                run: "npm publish",
                env: {
                  NPM_TOKEN: "${{ secrets.NPM_TOKEN }}",
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
