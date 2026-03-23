import { describe, expect, it } from "vitest";
import { detectWorkflowArtifactTrustChain } from "../../src/layer2-static/detectors/workflow-artifact-trust-chain";

describe("workflow artifact trust chain detector", () => {
  it("flags untrusted artifact producer consumed by privileged job that executes commands", () => {
    const findings = detectWorkflowArtifactTrustChain({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request]
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: dist
  release:
    needs: build
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
      - run: ./dist/release.sh
`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/upload-artifact@v4",
                with: {
                  name: "dist",
                },
              },
            ],
          },
          release: {
            needs: "build",
            permissions: {
              contents: "write",
            },
            steps: [
              {
                uses: "actions/download-artifact@v4",
                with: {
                  name: "dist",
                },
              },
              {
                run: "./dist/release.sh",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-artifact-trust-chain");
  });

  it("does not flag artifact transfers on trusted triggers", () => {
    const findings = detectWorkflowArtifactTrustChain({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [push]
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: dist
  release:
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
      - run: ./dist/release.sh
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/upload-artifact@v4",
                with: {
                  name: "dist",
                },
              },
            ],
          },
          release: {
            permissions: {
              contents: "write",
            },
            steps: [
              {
                uses: "actions/download-artifact@v4",
                with: {
                  name: "dist",
                },
              },
              {
                run: "./dist/release.sh",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
