import { describe, expect, it } from "vitest";
import { detectDependabotCooldown } from "../../src/layer2-static/detectors/dependabot-cooldown";

describe("dependabot cooldown detector", () => {
  it("flags updates that omit cooldown settings", () => {
    const findings = detectDependabotCooldown({
      filePath: ".github/dependabot.yml",
      textContent: `version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n`,
      parsed: {
        version: 2,
        updates: [
          {
            "package-ecosystem": "npm",
            directory: "/",
            schedule: {
              interval: "daily",
            },
          },
        ],
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("dependabot-cooldown");
  });

  it("does not flag updates with cooldown policy", () => {
    const findings = detectDependabotCooldown({
      filePath: ".github/dependabot.yml",
      textContent: `version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n    cooldown:\n      default-days: 3\n`,
      parsed: {
        version: 2,
        updates: [
          {
            "package-ecosystem": "npm",
            directory: "/",
            schedule: {
              interval: "daily",
            },
            cooldown: {
              "default-days": 3,
            },
          },
        ],
      },
    });

    expect(findings).toHaveLength(0);
  });
});
