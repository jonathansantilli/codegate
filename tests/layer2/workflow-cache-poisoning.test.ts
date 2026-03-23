import { describe, expect, it } from "vitest";
import { detectWorkflowCachePoisoning } from "../../src/layer2-static/detectors/workflow-cache-poisoning";

describe("workflow cache poisoning detector", () => {
  it("flags restore keys in pull request workflows", () => {
    const textContent = `name: cache
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: deps-\${{ github.sha }}
          restore-keys: |
            deps-
`;

    const findings = detectWorkflowCachePoisoning({
      filePath: ".github/workflows/cache.yml",
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/cache@v4",
                with: {
                  path: "~/.cache",
                  key: "deps-${{ github.sha }}",
                  "restore-keys": "deps-",
                },
              },
            ],
          },
        },
      },
      textContent,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-cache-poisoning");
    expect(findings[0]?.location.field).toContain("restore-keys");
    expect(findings[0]?.evidence).toContain("restore-keys");
  });

  it("does not flag restore keys in push-only workflows", () => {
    const findings = detectWorkflowCachePoisoning({
      filePath: ".github/workflows/cache.yml",
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/cache@v4",
                with: {
                  path: "~/.cache",
                  key: "deps-${{ github.sha }}",
                  "restore-keys": "deps-",
                },
              },
            ],
          },
        },
      },
      textContent: "",
    });

    expect(findings).toHaveLength(0);
  });
});
