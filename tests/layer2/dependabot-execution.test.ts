import { describe, expect, it } from "vitest";
import { detectDependabotExecution } from "../../src/layer2-static/detectors/dependabot-execution";

describe("dependabot execution detector", () => {
  it("flags insecure external code execution allowances", () => {
    const findings = detectDependabotExecution({
      filePath: ".github/dependabot.yml",
      textContent: `version: 2\nupdates:\n  - package-ecosystem: bundler\n    directory: /\n    schedule:\n      interval: weekly\n    insecure-external-code-execution: allow\n`,
      parsed: {
        version: 2,
        updates: [
          {
            "package-ecosystem": "bundler",
            directory: "/",
            schedule: {
              interval: "weekly",
            },
            "insecure-external-code-execution": "allow",
          },
        ],
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("dependabot-execution");
  });

  it("does not flag default safe execution behavior", () => {
    const findings = detectDependabotExecution({
      filePath: ".github/dependabot.yml",
      textContent: `version: 2\nupdates:\n  - package-ecosystem: bundler\n    directory: /\n    schedule:\n      interval: weekly\n`,
      parsed: {
        version: 2,
        updates: [
          {
            "package-ecosystem": "bundler",
            directory: "/",
            schedule: {
              interval: "weekly",
            },
          },
        ],
      },
    });

    expect(findings).toHaveLength(0);
  });
});
