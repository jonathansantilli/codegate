import { describe, expect, it } from "vitest";
import { detectWorkflowHardcodedContainerCredentials } from "../../src/layer2-static/detectors/workflow-hardcoded-container-credentials";

describe("workflow hardcoded container credentials detector", () => {
  it("flags container image references that embed credentials", () => {
    const findings = detectWorkflowHardcodedContainerCredentials({
      filePath: ".github/workflows/deploy.yml",
      textContent: `on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/myuser:mypassword@ghcr.io/org/private-image:latest
    steps:
      - run: echo deploy
`,
      parsed: {
        on: ["push"],
        jobs: {
          deploy: {
            "runs-on": "ubuntu-latest",
            container: {
              image: "ghcr.io/myuser:mypassword@ghcr.io/org/private-image:latest",
            },
            steps: [{ run: "echo deploy" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("hardcoded-container-credentials");
  });

  it("does not flag normal image references", () => {
    const findings = detectWorkflowHardcodedContainerCredentials({
      filePath: ".github/workflows/deploy.yml",
      textContent: `on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/org/private-image:latest
    steps:
      - run: echo deploy
`,
      parsed: {
        on: ["push"],
        jobs: {
          deploy: {
            "runs-on": "ubuntu-latest",
            container: {
              image: "ghcr.io/org/private-image:latest",
            },
            steps: [{ run: "echo deploy" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
