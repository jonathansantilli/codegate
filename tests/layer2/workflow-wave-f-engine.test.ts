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
  persona: "auditor",
  runtimeMode: "offline",
  workflowAuditsEnabled: true,
};

describe("workflow wave F engine integration", () => {
  it("surfaces workflow-pr-target-checkout-head findings through runStaticEngine", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/release.yml",
          format: "yaml",
          textContent: `on: [pull_request_target]
jobs:
  release:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`,
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

    const ruleIds = new Set(findings.map((finding) => finding.rule_id));
    expect(ruleIds.has("workflow-pr-target-checkout-head")).toBe(true);
  });
});
