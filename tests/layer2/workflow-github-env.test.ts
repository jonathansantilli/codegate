import { describe, expect, it } from "vitest";
import { detectWorkflowGithubEnv } from "../../src/layer2-static/detectors/workflow-github-env";

describe("workflow github env detector", () => {
  it("flags writes to GITHUB_ENV from a run step", () => {
    const findings = detectWorkflowGithubEnv({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TOKEN=foo" >> "$GITHUB_ENV"
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            steps: [{ run: 'echo "TOKEN=foo" >> "$GITHUB_ENV"' }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-github-env");
    expect(findings[0]?.evidence).toContain("GITHUB_ENV");
  });

  it("does not flag writes to GITHUB_OUTPUT", () => {
    const findings = detectWorkflowGithubEnv({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TOKEN=foo" >> "$GITHUB_OUTPUT"
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            steps: [{ run: 'echo "TOKEN=foo" >> "$GITHUB_OUTPUT"' }],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
