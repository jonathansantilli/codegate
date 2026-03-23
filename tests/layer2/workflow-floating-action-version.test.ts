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

describe("workflow floating action version detector", () => {
  it("flags action inputs that set version selectors to latest", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/security.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              trivy: {
                steps: [
                  {
                    uses: "aquasecurity/setup-trivy@v0.2.6",
                    with: {
                      version: "latest",
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

    expect(findings.some((finding) => finding.rule_id === "workflow-floating-action-version")).toBe(
      true,
    );
  });

  it("does not flag action inputs pinned to explicit versions", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/security.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              trivy: {
                steps: [
                  {
                    uses: "aquasecurity/setup-trivy@v0.2.6",
                    with: {
                      version: "0.69.5",
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

    expect(findings.some((finding) => finding.rule_id === "workflow-floating-action-version")).toBe(
      false,
    );
  });
});
