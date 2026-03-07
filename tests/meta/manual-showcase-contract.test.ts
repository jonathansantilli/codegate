import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());
const scenarioIds = Array.from(
  { length: 29 },
  (_, index) => `SG-${String(index).padStart(2, "0")}`,
);
const userScopeScenarioIds = new Set(["SG-10"]);

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(resolve(root, path), "utf8")) as unknown;
}

function assertExpectedShape(value: unknown): void {
  expect(typeof value).toBe("object");
  expect(value).not.toBeNull();
  const record = value as Record<string, unknown>;

  expect(typeof record.command).toBe("string");
  expect(typeof record.expectedExitCode).toBe("number");
  expect(Array.isArray(record.expectedSignals)).toBe(true);
  if (record.expectedFiles !== undefined) {
    expect(Array.isArray(record.expectedFiles)).toBe(true);
  }
  if (record.interactive !== undefined) {
    expect(typeof record.interactive).toBe("boolean");
  }
}

function readExpected(id: string): Record<string, unknown> {
  return readJson(`showcase/scenarios/${id}/expected.json`) as Record<string, unknown>;
}

function readProjectConfig(id: string): Record<string, unknown> | null {
  const configPath = resolve(root, `showcase/scenarios/${id}/project/.codegate.json`);
  if (!existsSync(configPath)) {
    return null;
  }
  return JSON.parse(readFileSync(configPath, "utf8")) as Record<string, unknown>;
}

describe("manual showcase contract", () => {
  it("includes required showcase docs when private showcase pack is present", () => {
    const hasShowcasePack =
      existsSync(resolve(root, "showcase/README.md")) ||
      existsSync(resolve(root, "docs/showcase/scenario-matrix.md"));
    if (!hasShowcasePack) {
      expect(true).toBe(true);
      return;
    }

    expect(existsSync(resolve(root, "showcase/README.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/showcase/scenario-matrix.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/showcase/manual-integration-runbook.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/showcase/evidence-capture-template.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/showcase/feature-demo-index.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/showcase/blog-video-outline.md"))).toBe(true);
  });

  it("contains all scenario packs with notes and expected schema when private showcase pack is present", () => {
    const hasScenarioMatrix = existsSync(resolve(root, "docs/showcase/scenario-matrix.md"));
    const hasScenarioRoot = existsSync(resolve(root, "showcase/scenarios"));
    if (!hasScenarioMatrix || !hasScenarioRoot) {
      expect(true).toBe(true);
      return;
    }

    for (const id of scenarioIds) {
      const matches = readFileSync(
        resolve(root, "docs/showcase/scenario-matrix.md"),
        "utf8",
      ).includes(`\`${id}\``);
      expect(matches).toBe(true);

      const scenarioDir = resolve(root, `showcase/scenarios/${id}`);
      expect(existsSync(resolve(scenarioDir, "notes.md"))).toBe(true);
      expect(existsSync(resolve(scenarioDir, "expected.json"))).toBe(true);
      assertExpectedShape(readJson(`showcase/scenarios/${id}/expected.json`));
    }
  });

  it("makes non-user-scope project scenarios hermetic", () => {
    const hasScenarioRoot = existsSync(resolve(root, "showcase/scenarios"));
    if (!hasScenarioRoot) {
      expect(true).toBe(true);
      return;
    }

    for (const id of scenarioIds) {
      const projectDir = resolve(root, `showcase/scenarios/${id}/project`);
      const command = readExpected(id).command;
      const commandString = typeof command === "string" ? command : "";
      const usesProjectFixture =
        commandString.includes(`showcase/scenarios/${id}/project`) ||
        commandString.includes(`cd "$TMP/project"`);

      if (!existsSync(projectDir) || userScopeScenarioIds.has(id) || !usesProjectFixture) {
        continue;
      }

      const config = readProjectConfig(id);
      expect(
        config,
        `${id} should include project/.codegate.json to isolate the fixture`,
      ).not.toBeNull();
      expect(
        config?.scan_user_scope,
        `${id} should disable user-scope scanning for deterministic showcase runs`,
      ).toBe(false);
    }
  });

  it("does not use removed run --format options in showcase commands", () => {
    const hasScenarioRoot = existsSync(resolve(root, "showcase/scenarios"));
    if (!hasScenarioRoot) {
      expect(true).toBe(true);
      return;
    }

    for (const id of scenarioIds) {
      const command = readExpected(id).command;
      expect(typeof command).toBe("string");
      const commandString = command as string;
      const usesRunCommand = commandString.includes(" run ");
      if (!usesRunCommand) {
        continue;
      }

      expect(commandString, `${id} uses removed run --format showcase syntax`).not.toContain(
        "--format",
      );
    }
  });
});
