import { describe, expect, it } from "vitest";
import { detectWorkflowBotConditions } from "../../src/layer2-static/detectors/workflow-bot-conditions";

describe("workflow bot conditions detector", () => {
  it("flags bot-actor conditions that guard privileged operations", () => {
    const findings = detectWorkflowBotConditions({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - if: github.actor == 'dependabot[bot]'
        run: npm publish
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          release: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                if: "github.actor == 'dependabot[bot]'",
                run: "npm publish",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("bot-conditions");
  });

  it("does not flag bot conditions on non-privileged steps", () => {
    const findings = detectWorkflowBotConditions({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request]
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - if: github.actor == 'dependabot[bot]'
        run: npm run lint
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          checks: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                if: "github.actor == 'dependabot[bot]'",
                run: "npm run lint",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
