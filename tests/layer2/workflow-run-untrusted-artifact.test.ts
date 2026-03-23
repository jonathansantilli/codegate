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

describe("workflow run untrusted artifact detector", () => {
  it("flags privileged workflow_run jobs that download artifacts and execute commands without guards", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/deploy.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: {
              workflow_run: {
                workflows: ["CI"],
                types: ["completed"],
              },
            },
            jobs: {
              deploy: {
                permissions: {
                  contents: "write",
                },
                steps: [
                  {
                    uses: "actions/download-artifact@v4",
                    with: {
                      name: "build-output",
                    },
                  },
                  {
                    run: "./deploy.sh",
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

    expect(findings.some((finding) => finding.rule_id === "workflow-run-untrusted-artifact")).toBe(
      true,
    );
  });

  it("does not flag guarded workflow_run jobs with strict origin checks", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/deploy.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: {
              workflow_run: {
                workflows: ["CI"],
                types: ["completed"],
                branches: ["main"],
              },
            },
            jobs: {
              deploy: {
                if: "github.event.workflow_run.event != 'pull_request' && github.event.workflow_run.head_branch == 'main'",
                permissions: {
                  contents: "write",
                },
                steps: [
                  {
                    uses: "actions/download-artifact@v4",
                    with: {
                      name: "build-output",
                    },
                  },
                  {
                    run: "./deploy.sh",
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

    expect(findings.some((finding) => finding.rule_id === "workflow-run-untrusted-artifact")).toBe(
      false,
    );
  });
});
