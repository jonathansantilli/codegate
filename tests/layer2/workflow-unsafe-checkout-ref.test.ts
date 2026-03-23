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

describe("workflow unsafe checkout ref detector", () => {
  it("flags privileged pull_request_target checkout that uses head.ref", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/release.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request_target"],
            jobs: {
              release: {
                permissions: {
                  contents: "write",
                },
                steps: [
                  {
                    uses: "actions/checkout@v4",
                    with: {
                      ref: "${{ github.event.pull_request.head.ref }}",
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

    expect(findings.some((finding) => finding.rule_id === "workflow-unsafe-checkout-ref")).toBe(
      true,
    );
  });

  it("does not flag checkout pinned to head.sha", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/release.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request_target"],
            jobs: {
              release: {
                permissions: {
                  contents: "write",
                },
                steps: [
                  {
                    uses: "actions/checkout@v4",
                    with: {
                      ref: "${{ github.event.pull_request.head.sha }}",
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

    expect(findings.some((finding) => finding.rule_id === "workflow-unsafe-checkout-ref")).toBe(
      false,
    );
  });
});
