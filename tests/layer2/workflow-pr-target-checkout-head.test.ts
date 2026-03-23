import { describe, expect, it } from "vitest";
import { detectWorkflowPrTargetCheckoutHead } from "../../src/layer2-static/detectors/workflow-pr-target-checkout-head";

describe("workflow pr-target checkout head detector", () => {
  it("flags pull_request_target workflows that checkout PR head with write permissions", () => {
    const findings = detectWorkflowPrTargetCheckoutHead({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request_target]
jobs:
  release:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`,
      parsed: {
        on: ["pull_request_target"],
        jobs: {
          release: {
            permissions: {
              contents: "write",
            },
            steps: [
              {
                uses: "actions/checkout@v4",
                with: {
                  ref: "${{ github.event.pull_request.head.sha }}",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-pr-target-checkout-head");
    expect(findings[0]?.severity).toBe("CRITICAL");
  });

  it("flags pull_request_target checkout of PR head even without explicit write permissions", () => {
    const findings = detectWorkflowPrTargetCheckoutHead({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request_target]
jobs:
  verify:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.ref }}
`,
      parsed: {
        on: ["pull_request_target"],
        jobs: {
          verify: {
            steps: [
              {
                uses: "actions/checkout@v4",
                with: {
                  ref: "${{ github.event.pull_request.head.ref }}",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("HIGH");
  });

  it("does not flag pull_request workflows", () => {
    const findings = detectWorkflowPrTargetCheckoutHead({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request]
jobs:
  release:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          release: {
            permissions: {
              contents: "write",
            },
            steps: [
              {
                uses: "actions/checkout@v4",
                with: {
                  ref: "${{ github.event.pull_request.head.sha }}",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("does not flag pull_request_target workflows without risky checkout ref", () => {
    const findings = detectWorkflowPrTargetCheckoutHead({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request_target]
jobs:
  release:
    steps:
      - uses: actions/checkout@v4
`,
      parsed: {
        on: ["pull_request_target"],
        jobs: {
          release: {
            steps: [
              {
                uses: "actions/checkout@v4",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
