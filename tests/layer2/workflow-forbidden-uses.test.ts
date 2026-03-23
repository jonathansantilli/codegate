import { describe, expect, it } from "vitest";
import { detectWorkflowForbiddenUses } from "../../src/layer2-static/detectors/workflow-forbidden-uses";

describe("workflow forbidden uses detector", () => {
  it("flags repository actions outside an allowlist", () => {
    const findings = detectWorkflowForbiddenUses({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@v4",
              },
            ],
          },
        },
      },
      config: {
        allow: ["github/codeql-action/*"],
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-forbidden-uses");
    expect(findings[0]?.evidence).toContain("actions/checkout@v4");
  });

  it("flags repository actions matching a denylist and ignores local and docker uses", () => {
    const findings = detectWorkflowForbiddenUses({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.20
      - uses: ./.github/actions/local
      - uses: actions/checkout@v4
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "docker://alpine:3.20",
              },
              {
                uses: "./.github/actions/local",
              },
              {
                uses: "actions/checkout@v4",
              },
            ],
          },
        },
      },
      config: {
        deny: ["actions/*"],
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-forbidden-uses");
    expect(findings[0]?.evidence).toContain("actions/checkout@v4");
  });

  it("applies allowlist policy to reusable workflow references at job level", () => {
    const findings = detectWorkflowForbiddenUses({
      filePath: ".github/workflows/release.yml",
      textContent: `name: release
on: workflow_dispatch
jobs:
  publish:
    uses: org/repo/.github/workflows/release.yml@v2
`,
      parsed: {
        on: ["workflow_dispatch"],
        jobs: {
          publish: {
            uses: "org/repo/.github/workflows/release.yml@v2",
          },
        },
      },
      config: {
        allow: ["github/codeql-action/*"],
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-forbidden-uses");
    expect(findings[0]?.location.field).toBe("jobs.publish.uses");
  });
});
