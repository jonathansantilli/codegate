import { describe, expect, it } from "vitest";
import { detectWorkflowUndocumentedPermissions } from "../../src/layer2-static/detectors/workflow-undocumented-permissions";

describe("workflow undocumented permissions detector", () => {
  it("flags write permissions without comments", () => {
    const textContent = `name: release
on: push
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - run: npm publish
`;

    const findings = detectWorkflowUndocumentedPermissions({
      filePath: ".github/workflows/release.yml",
      parsed: {
        on: ["push"],
        permissions: {
          contents: "write",
        },
        jobs: {
          publish: {
            permissions: {
              packages: "write",
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

    expect(findings.length).toBeGreaterThan(0);
    expect(
      findings.some((finding) => finding.rule_id === "workflow-undocumented-permissions"),
    ).toBe(true);
  });

  it("ignores documented permissions comments", () => {
    const textContent = `name: release
on: push
permissions: # ok
  contents: write # needed for release metadata
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      packages: write # needed to publish
    steps:
      - run: npm publish
`;

    const findings = detectWorkflowUndocumentedPermissions({
      filePath: ".github/workflows/release.yml",
      parsed: {
        on: ["push"],
        permissions: {
          contents: "write",
        },
        jobs: {
          publish: {
            permissions: {
              packages: "write",
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
