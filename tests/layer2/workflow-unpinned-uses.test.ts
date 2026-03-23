import { describe, expect, it } from "vitest";
import { runStaticEngine, type StaticEngineConfig } from "../../src/layer2-static/engine";

const BASE_CONFIG: StaticEngineConfig = {
  knownSafeMcpServers: [],
  knownSafeFormatters: [],
  knownSafeLspServers: [],
  knownSafeHooks: [],
  blockedCommands: ["bash", "sh"],
  trustedApiDomains: [],
  unicodeAnalysis: true,
  checkIdeSettings: true,
  persona: "regular",
  runtimeMode: "offline",
  workflowAuditsEnabled: true,
};

describe("workflow unpinned uses detector", () => {
  it("flags unpinned repository action refs", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/ci.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request"],
            jobs: {
              test: {
                steps: [{ uses: "actions/checkout@v4" }, { uses: "./.github/actions/local" }],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-unpinned-uses")).toBe(true);
  });

  it("does not flag hash-pinned refs", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/ci.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              test: {
                steps: [
                  {
                    uses: "actions/checkout@0123456789abcdef0123456789abcdef01234567",
                  },
                ],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-unpinned-uses")).toBe(false);
  });

  it("flags unpinned reusable workflow refs at job level", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/release.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["workflow_dispatch"],
            jobs: {
              release: {
                uses: "org/repo/.github/workflows/reusable-release.yml@v2",
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-unpinned-uses")).toBe(true);
  });
});
