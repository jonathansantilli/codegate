import { describe, expect, it } from "vitest";
import { detectWorkflowOidcUntrustedContext } from "../../src/layer2-static/detectors/workflow-oidc-untrusted-context";

describe("workflow oidc untrusted context detector", () => {
  it("flags id-token write in untrusted trigger without strict trust checks or audience constraints", () => {
    const findings = detectWorkflowOidcUntrustedContext({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request_target]
jobs:
  release:
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          aws-region: us-east-1
`,
      parsed: {
        on: ["pull_request_target"],
        jobs: {
          release: {
            permissions: {
              "id-token": "write",
              contents: "read",
            },
            steps: [
              {
                uses: "aws-actions/configure-aws-credentials@v4",
                with: {
                  "role-to-assume": "arn:aws:iam::123456789012:role/deploy",
                  "aws-region": "us-east-1",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-oidc-untrusted-context");
    expect(findings[0]?.severity).toBe("HIGH");
  });

  it("does not flag when strict actor/repository gating and audience constraints are present", () => {
    const findings = detectWorkflowOidcUntrustedContext({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request_target]
jobs:
  release:
    if: github.actor == 'dependabot[bot]' && github.repository == github.event.pull_request.head.repo.full_name
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          audience: sts.amazonaws.com
`,
      parsed: {
        on: ["pull_request_target"],
        jobs: {
          release: {
            if: "github.actor == 'dependabot[bot]' && github.repository == github.event.pull_request.head.repo.full_name",
            permissions: {
              "id-token": "write",
              contents: "read",
            },
            steps: [
              {
                uses: "aws-actions/configure-aws-credentials@v4",
                with: {
                  "role-to-assume": "arn:aws:iam::123456789012:role/deploy",
                  audience: "sts.amazonaws.com",
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
