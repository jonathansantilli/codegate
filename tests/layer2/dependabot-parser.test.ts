import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createScanDiscoveryContext } from "../../src/scan";
import {
  extractDependabotFacts,
  isGitHubDependabotPath,
} from "../../src/layer2-static/dependabot/parser";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "codegate-dependabot-parser-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("dependabot parser", () => {
  it("detects Dependabot config file paths", () => {
    expect(isGitHubDependabotPath(".github/dependabot.yml")).toBe(true);
    expect(isGitHubDependabotPath(".github/dependabot.yaml")).toBe(true);
    expect(isGitHubDependabotPath("nested/.github/dependabot.yml")).toBe(true);
    expect(isGitHubDependabotPath(".github/workflows/ci.yml")).toBe(false);
    expect(isGitHubDependabotPath("dependabot.yml")).toBe(false);
  });

  it("extracts structured Dependabot facts from parsed yaml structures", () => {
    const facts = extractDependabotFacts({
      version: 2,
      updates: [
        {
          "package-ecosystem": "npm",
          directory: "/",
          schedule: {
            interval: "weekly",
            day: "monday",
            time: "06:00",
            timezone: "Etc/UTC",
          },
          "open-pull-requests-limit": 5,
          cooldown: {
            "default-days": 3,
            "semver-major-days": 7,
          },
          labels: ["dependencies", "javascript"],
          "commit-message": {
            prefix: "chore",
            "prefix-development": "chore",
            include: "scope",
          },
          groups: {
            "npm-production": {
              "dependency-type": "production",
              "update-types": ["minor", "patch"],
              patterns: ["*"],
            },
          },
        },
      ],
    });

    expect(facts).not.toBeNull();
    expect(facts?.version).toBe(2);
    expect(facts?.updates).toHaveLength(1);
    expect(facts?.updates?.[0]?.packageEcosystem).toBe("npm");
    expect(facts?.updates?.[0]?.directory).toBe("/");
    expect(facts?.updates?.[0]?.schedule?.interval).toBe("weekly");
    expect(facts?.updates?.[0]?.schedule?.day).toBe("monday");
    expect(facts?.updates?.[0]?.schedule?.time).toBe("06:00");
    expect(facts?.updates?.[0]?.openPullRequestsLimit).toBe(5);
    expect(facts?.updates?.[0]?.cooldown?.defaultDays).toBe(3);
    expect(facts?.updates?.[0]?.cooldown?.semverMajorDays).toBe(7);
    expect(facts?.updates?.[0]?.labels).toEqual(["dependencies", "javascript"]);
    expect(facts?.updates?.[0]?.commitMessage?.prefix).toBe("chore");
    expect(facts?.updates?.[0]?.groups?.["npm-production"]?.dependencyType).toBe("production");
  });

  it("returns null for empty or unrelated yaml structures", () => {
    expect(extractDependabotFacts({})).toBeNull();
    expect(extractDependabotFacts({ version: "not-a-number" })).toBeNull();
    expect(extractDependabotFacts({ updates: ["broken"] })).toBeNull();
  });

  it("discovers dependabot configs during scan selection", () => {
    const root = createTempDir();
    const dependabotPath = join(root, ".github", "dependabot.yml");
    mkdirSync(join(root, ".github"), { recursive: true });
    writeFileSync(
      dependabotPath,
      [
        "version: 2",
        "updates:",
        "  - package-ecosystem: npm",
        "    directory: /",
        "    schedule:",
        "      interval: weekly",
      ].join("\n"),
      "utf8",
    );

    const context = createScanDiscoveryContext(root, undefined, {
      parseSelected: true,
      collectModes: ["default"],
    });

    expect(context.selected.map((candidate) => candidate.reportPath)).toContain(
      ".github/dependabot.yml",
    );
    expect(
      context.parsedCandidates?.some(
        (candidate) => candidate.reportPath === ".github/dependabot.yml",
      ),
    ).toBe(true);
  });
});
