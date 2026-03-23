import { describe, expect, it } from "vitest";
import { detectWorkflowCallBoundary } from "../../src/layer2-static/detectors/workflow-call-boundary";

describe("workflow call boundary detector", () => {
  it("flags undeclared workflow_call secrets referenced by jobs", () => {
    const findings = detectWorkflowCallBoundary({
      filePath: ".github/workflows/reusable.yml",
      textContent: `on:
  workflow_call:
    inputs:
      config_path:
        required: true
        type: string
jobs:
  run:
    steps:
      - run: echo \${{ secrets.publish_token }}
`,
      parsed: {
        on: {
          workflow_call: {
            inputs: {
              config_path: {
                required: true,
                type: "string",
              },
            },
          },
        },
        jobs: {
          run: {
            steps: [
              {
                run: "echo ${{ secrets.publish_token }}",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-call-boundary");
    expect(findings[0]?.description).toContain("secret");
  });

  it("flags undeclared workflow_call inputs referenced by jobs", () => {
    const findings = detectWorkflowCallBoundary({
      filePath: ".github/workflows/reusable.yml",
      textContent: `on:
  workflow_call:
    secrets:
      publish_token:
        required: true
jobs:
  run:
    steps:
      - run: echo \${{ inputs.channel }}
`,
      parsed: {
        on: {
          workflow_call: {
            secrets: {
              publish_token: {
                required: true,
              },
            },
          },
        },
        jobs: {
          run: {
            steps: [
              {
                run: "echo ${{ inputs.channel }}",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.description).toContain("input");
  });

  it("does not flag when workflow_call references are explicitly declared", () => {
    const findings = detectWorkflowCallBoundary({
      filePath: ".github/workflows/reusable.yml",
      textContent: `on:
  workflow_call:
    inputs:
      channel:
        required: true
        type: string
    secrets:
      publish_token:
        required: true
jobs:
  run:
    steps:
      - run: echo \${{ inputs.channel }} \${{ secrets.publish_token }}
`,
      parsed: {
        on: {
          workflow_call: {
            inputs: {
              channel: {
                required: true,
                type: "string",
              },
            },
            secrets: {
              publish_token: {
                required: true,
              },
            },
          },
        },
        jobs: {
          run: {
            steps: [
              {
                run: "echo ${{ inputs.channel }} ${{ secrets.publish_token }}",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
