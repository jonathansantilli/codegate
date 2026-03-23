import { describe, expect, it } from "vitest";
import { detectWorkflowInsecureCommands } from "../../src/layer2-static/detectors/workflow-insecure-commands";

describe("workflow insecure commands detector", () => {
  it("flags curl piped directly into a shell", () => {
    const findings = detectWorkflowInsecureCommands({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/install.sh | sh
`,
      parsed: {
        on: ["push"],
        jobs: {
          install: {
            steps: [{ run: "curl -fsSL https://example.com/install.sh | sh" }],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-insecure-commands");
    expect(findings[0]?.evidence).toContain("curl -fsSL https://example.com/install.sh | sh");
  });

  it("does not flag download and execute flows that do not pipe into a shell", () => {
    const findings = detectWorkflowInsecureCommands({
      filePath: ".github/workflows/ci.yml",
      textContent: `name: ci
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/install.sh -o install.sh
      - run: sh install.sh
`,
      parsed: {
        on: ["push"],
        jobs: {
          install: {
            steps: [
              { run: "curl -fsSL https://example.com/install.sh -o install.sh" },
              { run: "sh install.sh" },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
