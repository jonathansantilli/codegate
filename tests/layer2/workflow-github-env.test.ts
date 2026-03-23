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
    expect(findings[0]?.rule_id).toBe("workflow-command-file-poisoning");
    expect(findings[0]?.evidence).toContain("GITHUB_ENV");
  });

  it("flags writes to GITHUB_OUTPUT on untrusted workflow triggers", () => {
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

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-command-file-poisoning");
    expect(findings[0]?.evidence).toContain("GITHUB_OUTPUT");
  });

  it("flags writes to GITHUB_PATH on untrusted workflow triggers", () => {
    const findings = detectWorkflowGithubEnv({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "/tmp/evil" >> "$GITHUB_PATH"
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            steps: [{ run: 'echo "/tmp/evil" >> "$GITHUB_PATH"' }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-command-file-poisoning");
    expect(findings[0]?.evidence).toContain("GITHUB_PATH");
  });

  it("flags writes to GITHUB_STATE on untrusted workflow triggers", () => {
    const findings = detectWorkflowGithubEnv({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "state=unsafe" >> "$GITHUB_STATE"
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            steps: [{ run: 'echo "state=unsafe" >> "$GITHUB_STATE"' }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-command-file-poisoning");
    expect(findings[0]?.evidence).toContain("GITHUB_STATE");
  });

  it("does not flag command-file writes in trusted push-only workflows", () => {
    const findings = detectWorkflowGithubEnv({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "value=ok" >> "$GITHUB_OUTPUT"
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [{ run: 'echo "value=ok" >> "$GITHUB_OUTPUT"' }],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
