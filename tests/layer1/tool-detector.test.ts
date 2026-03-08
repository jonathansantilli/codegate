import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  detectTools,
  type ToolDetectorDeps,
  type ToolName,
} from "../../src/layer1-discovery/tool-detector";

function makeDeps(overrides: Partial<ToolDetectorDeps>): ToolDetectorDeps {
  return {
    platform: "darwin",
    homedir: "/Users/tester",
    which: () => undefined,
    execVersion: () => null,
    pathExists: () => false,
    listDirectory: () => [],
    ...overrides,
  };
}

function byName(
  detections: ReturnType<typeof detectTools>,
  name: ToolName,
): (typeof detections)[number] {
  const match = detections.find((d) => d.tool === name);
  if (!match) {
    throw new Error(`missing detection for ${name}`);
  }
  return match;
}

describe("task 10 tool detector", () => {
  it("detects CLI tools from PATH and captures version", () => {
    const detections = detectTools(
      makeDeps({
        which: (binary) => (binary === "claude" ? "/usr/local/bin/claude" : undefined),
        execVersion: (binary) => (binary === "claude" ? "1.0.33" : null),
      }),
    );

    const claude = byName(detections, "claude-code");
    expect(claude.installed).toBe(true);
    expect(claude.version).toBe("1.0.33");
    expect(claude.path).toBe("/usr/local/bin/claude");
  });

  it("detects GUI app-bundle install paths", () => {
    const detections = detectTools(
      makeDeps({
        pathExists: (path) => path === "/Applications/Cursor.app",
      }),
    );
    const cursor = byName(detections, "cursor");
    expect(cursor.installed).toBe(true);
    expect(cursor.source).toBe("app-bundle");
  });

  it("detects GitHub Copilot extension installation", () => {
    const extensionsDir = join("/Users/tester", ".vscode", "extensions");
    const detections = detectTools(
      makeDeps({
        listDirectory: (path) =>
          path === extensionsDir ? ["github.copilot-1.2.3", "some.other-ext-0.1.0"] : [],
      }),
    );
    const copilot = byName(detections, "github-copilot");
    expect(copilot.installed).toBe(true);
    expect(copilot.version).toBe("1.2.3");
    expect(copilot.source).toBe("extension");
  });

  it("detects JetBrains via Toolbox installation paths", () => {
    const detections = detectTools(
      makeDeps({
        pathExists: (path) => path === "/Applications/JetBrains Toolbox/JetBrains Toolbox.app",
      }),
    );
    const jetbrains = byName(detections, "jetbrains");
    expect(jetbrains.installed).toBe(true);
    expect(jetbrains.source).toBe("app-bundle");
    expect(jetbrains.path).toBe("/Applications/JetBrains Toolbox/JetBrains Toolbox.app");
  });
});
