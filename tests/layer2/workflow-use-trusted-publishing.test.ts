import { describe, expect, it } from "vitest";
import { detectWorkflowUseTrustedPublishing } from "../../src/layer2-static/detectors/workflow-use-trusted-publishing";

describe("workflow trusted publishing detector", () => {
  it("flags token-based npm publishing", () => {
    const textContent = `name: release
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: \${{ secrets.NPM_TOKEN }}
`;

    const findings = detectWorkflowUseTrustedPublishing({
      filePath: ".github/workflows/release.yml",
      parsed: {
        on: {
          release: {
            types: ["published"],
          },
        },
        jobs: {
          publish: {
            steps: [
              {
                run: "npm publish",
              },
            ],
          },
        },
      },
      textContent,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-use-trusted-publishing");
    expect(findings[0]?.evidence).toContain("npm publish");
  });

  it("does not flag publish steps that already use id-token auth", () => {
    const textContent = `name: release
on:
  release:
    types: [published]
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - run: npm publish
`;

    const findings = detectWorkflowUseTrustedPublishing({
      filePath: ".github/workflows/release.yml",
      parsed: {
        on: {
          release: {
            types: ["published"],
          },
        },
        jobs: {
          publish: {
            permissions: {
              "id-token": "write",
            },
            steps: [
              {
                run: "npm publish",
              },
            ],
          },
        },
      },
      textContent,
    });

    expect(findings).toHaveLength(0);
  });
});
