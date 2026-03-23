import { describe, expect, it } from "vitest";
import { detectWorkflowMisfeature } from "../../src/layer2-static/detectors/workflow-misfeature";

describe("workflow misfeature detector", () => {
  it("flags security steps that continue on error", () => {
    const findings = detectWorkflowMisfeature({
      filePath: ".github/workflows/security.yml",
      textContent: `on: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - name: CodeQL Analysis\n        continue-on-error: true\n        run: codeql database analyze\n`,
      parsed: {
        on: ["push"],
        jobs: {
          scan: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                name: "CodeQL Analysis",
                "continue-on-error": true,
                run: "codeql database analyze",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-misfeature");
  });

  it("does not flag non-security steps with continue-on-error", () => {
    const findings = detectWorkflowMisfeature({
      filePath: ".github/workflows/build.yml",
      textContent: `on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - continue-on-error: true\n        run: npm run docs:preview\n`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            "runs-on": "ubuntu-latest",
            steps: [
              {
                "continue-on-error": true,
                run: "npm run docs:preview",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
