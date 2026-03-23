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

describe("workflow known vulnerable action detector", () => {
  it("runs only in online mode", async () => {
    const commonInput = {
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/ci.yml",
          format: "yaml" as const,
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              test: {
                steps: [{ uses: "actions/checkout@v3" }],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
    };

    const offline = await runStaticEngine({
      ...commonInput,
      config: {
        ...BASE_CONFIG,
        runtimeMode: "offline",
      },
    });

    const online = await runStaticEngine({
      ...commonInput,
      config: {
        ...BASE_CONFIG,
        runtimeMode: "online",
      },
    });

    expect(offline.some((finding) => finding.rule_id === "workflow-known-vuln-action")).toBe(false);
    expect(online.some((finding) => finding.rule_id === "workflow-known-vuln-action")).toBe(true);
  });
});
