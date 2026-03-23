import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createScanDiscoveryContext } from "../../src/scan";
import { extractActionFacts, isGitHubActionPath } from "../../src/layer2-static/action/parser";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "codegate-action-parser-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("action parser", () => {
  it("detects GitHub action file paths", () => {
    expect(isGitHubActionPath("action.yml")).toBe(true);
    expect(isGitHubActionPath("nested/action.yaml")).toBe(true);
    expect(isGitHubActionPath(".github/workflows/ci.yml")).toBe(false);
    expect(isGitHubActionPath("skills/security-review/SKILL.md")).toBe(false);
  });

  it("extracts composite action facts from parsed yaml structures", () => {
    const facts = extractActionFacts({
      name: "Composite Demo",
      description: "Example composite action",
      inputs: {
        token: {
          description: "Token for downstream steps",
          required: true,
        },
      },
      outputs: {
        digest: {
          description: "Computed digest",
          value: "${{ steps.compute.outputs.digest }}",
        },
      },
      runs: {
        using: "composite",
        steps: [
          {
            run: "echo hello",
          },
          {
            uses: "actions/checkout@v4",
            with: {
              repository: "owner/repo",
            },
          },
        ],
      },
    });

    expect(facts).not.toBeNull();
    expect(facts?.name).toBe("Composite Demo");
    expect(facts?.description).toBe("Example composite action");
    expect(facts?.inputs?.token?.required).toBe(true);
    expect(facts?.outputs?.digest?.value).toContain("${{");
    expect(facts?.runs?.using).toBe("composite");
    expect(facts?.runs?.steps).toHaveLength(2);
    expect(facts?.runs?.steps?.[0]?.run).toBe("echo hello");
    expect(facts?.runs?.steps?.[1]?.uses).toBe("actions/checkout@v4");
    expect(facts?.runs?.steps?.[1]?.with?.repository).toBe("owner/repo");
  });

  it("discovers action yaml files during scan selection", () => {
    const root = createTempDir();
    const actionPath = join(root, "action.yml");
    writeFileSync(
      actionPath,
      [
        "name: Composite Demo",
        "runs:",
        "  using: composite",
        "  steps:",
        "    - run: echo hello",
      ].join("\n"),
      "utf8",
    );

    const context = createScanDiscoveryContext(root, undefined, {
      parseSelected: true,
      collectModes: ["default"],
    });

    expect(context.selected.map((candidate) => candidate.reportPath)).toContain("action.yml");
    expect(
      context.parsedCandidates?.some((candidate) => candidate.reportPath === "action.yml"),
    ).toBe(true);

    const parsedAction = context.parsedCandidates?.find(
      (candidate) => candidate.reportPath === "action.yml",
    );
    expect(parsedAction?.parsed.ok).toBe(true);
    if (parsedAction?.parsed.ok) {
      expect(parsedAction.parsed.data.runs.using).toBe("composite");
    }
  });
});
