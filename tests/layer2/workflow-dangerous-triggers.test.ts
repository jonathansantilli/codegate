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

describe("workflow dangerous triggers detector", () => {
  it("flags pull_request_target trigger", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/pr.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: {
              pull_request_target: {},
            },
            jobs: {
              test: {
                steps: [{ run: "echo hi" }],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-dangerous-triggers")).toBe(
      true,
    );
  });

  it("does not flag safe triggers", async () => {
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
                steps: [{ run: "echo hi" }],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-dangerous-triggers")).toBe(
      false,
    );
  });
});
