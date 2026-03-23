import { describe, expect, it } from "vitest";
import { detectWorkflowSelfHostedRunner } from "../../src/layer2-static/detectors/workflow-self-hosted-runner";

describe("workflow self-hosted runner detector", () => {
  it("flags jobs that use self-hosted runners", () => {
    const findings = detectWorkflowSelfHostedRunner({
      filePath: ".github/workflows/deploy.yml",
      textContent: `name: deploy
on: push
jobs:
  deploy:
    runs-on: [self-hosted, linux]
    steps:
      - run: echo deploy
`,
      parsed: {
        on: ["push"],
        jobs: {
          deploy: {
            "runs-on": ["self-hosted", "linux"],
            steps: [{ run: "echo deploy" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-self-hosted-runner");
    expect(findings[0]?.evidence).toContain("self-hosted");
  });

  it("ignores hosted runners", () => {
    const findings = detectWorkflowSelfHostedRunner({
      filePath: ".github/workflows/deploy.yml",
      textContent: `jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
`,
      parsed: {
        on: ["push"],
        jobs: {
          deploy: {
            "runs-on": "ubuntu-latest",
            steps: [{ run: "echo deploy" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
