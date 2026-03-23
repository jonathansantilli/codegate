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

describe("workflow template injection detector", () => {
  it("flags template expansion in run steps on untrusted triggers", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/pr.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request"],
            jobs: {
              test: {
                steps: [
                  {
                    run: "echo ${{ github.event.pull_request.title }}",
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

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      true,
    );
  });

  it("flags known action sink inputs containing template expansions", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/pr.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request"],
            jobs: {
              test: {
                steps: [
                  {
                    uses: "actions/github-script@v7",
                    with: {
                      script: "core.info('${{ github.event.pull_request.title }}')",
                    },
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

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      true,
    );
  });

  it("does not flag template expansion in trusted push-only workflows", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/push.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              test: {
                steps: [
                  {
                    run: "echo ${{ github.ref }}",
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

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      false,
    );
  });
});
