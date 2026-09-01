import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runInventory } from "../../src/commands/inventory-command";

describe("inventory command — runInventory", () => {
  let home: string;
  let workspace: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "codegate-inv-home-"));
    workspace = mkdtempSync(join(tmpdir(), "codegate-inv-ws-"));
  });

  afterEach(() => {
    for (const dir of [home, workspace]) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  });

  it("lists tools + items using the real knowledge base", () => {
    const summary = runInventory({
      scope: "all",
      kind: "all",
      onlyExisting: false,
      workspaces: [workspace],
      homeDir: home,
    });

    expect(summary.kb_version).toBeTruthy();
    expect(summary.tools.length).toBeGreaterThan(0);
    // The real KB ships claude-code; sanity-check that.
    expect(summary.tools.some((t) => t.name === "claude-code")).toBe(true);
    expect(summary.items.length).toBeGreaterThan(0);
  });

  it("filters by kind=skills and kind=configs", () => {
    const skillsOnly = runInventory({
      scope: "all",
      kind: "skills",
      onlyExisting: false,
      workspaces: [workspace],
      homeDir: home,
    });
    expect(skillsOnly.items.every((i) => i.kind === "skill")).toBe(true);

    const configsOnly = runInventory({
      scope: "all",
      kind: "configs",
      onlyExisting: false,
      workspaces: [workspace],
      homeDir: home,
    });
    expect(configsOnly.items.every((i) => i.kind === "config")).toBe(true);
  });

  it("filters by scope=user", () => {
    const summary = runInventory({
      scope: "user",
      kind: "all",
      onlyExisting: false,
      workspaces: [workspace],
      homeDir: home,
    });
    expect(summary.items.every((i) => i.scope === "user")).toBe(true);
  });

  it("resolves non-wildcard paths against the correct root", () => {
    const summary = runInventory({
      scope: "all",
      kind: "configs",
      onlyExisting: false,
      workspaces: [workspace],
      homeDir: home,
    });
    const userItem = summary.items.find(
      (i) =>
        i.scope === "user" && i.tool === "claude-code" && i.pattern === ".claude/settings.json",
    );
    expect(userItem).toBeDefined();
    expect(userItem?.path.startsWith(home)).toBe(true);
    expect(userItem?.exists).toBe(false);
  });

  it("honors --only-existing for non-wildcard entries", () => {
    // Create a real file at ~/.claude/settings.json and workspace/.claude/settings.json
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(join(home, ".claude", "settings.json"), "{}");
    mkdirSync(join(workspace, ".claude"), { recursive: true });
    writeFileSync(join(workspace, ".claude", "settings.json"), "{}");

    const all = runInventory({
      scope: "all",
      kind: "configs",
      onlyExisting: true,
      workspaces: [workspace],
      homeDir: home,
    });
    // Only the entries we just created (plus possibly other tools' files if
    // the test host happens to have them) should appear.
    expect(all.items.every((i) => i.exists)).toBe(true);
    expect(
      all.items.some(
        (i) => i.tool === "claude-code" && i.path === join(home, ".claude", "settings.json"),
      ),
    ).toBe(true);
    expect(
      all.items.some(
        (i) => i.tool === "claude-code" && i.path === join(workspace, ".claude", "settings.json"),
      ),
    ).toBe(true);
  });

  it("expands wildcard skill_paths against the filesystem", () => {
    // Seed two Anthropic skills under the fake home
    mkdirSync(join(home, ".claude", "skills", "alpha"), { recursive: true });
    writeFileSync(join(home, ".claude", "skills", "alpha", "SKILL.md"), "# alpha");
    mkdirSync(join(home, ".claude", "skills", "beta"), { recursive: true });
    writeFileSync(join(home, ".claude", "skills", "beta", "SKILL.md"), "# beta");

    const summary = runInventory({
      scope: "user",
      kind: "skills",
      onlyExisting: true,
      workspaces: [workspace],
      homeDir: home,
    });

    const anthropicSkills = summary.items.filter(
      (i) => i.type === "anthropic_skill" && i.scope === "user",
    );
    const paths = anthropicSkills.map((i) => i.path).sort();
    expect(paths).toContain(join(home, ".claude", "skills", "alpha", "SKILL.md"));
    expect(paths).toContain(join(home, ".claude", "skills", "beta", "SKILL.md"));
  });

  it("skips project scope entries when no workspace is provided", () => {
    const summary = runInventory({
      scope: "project",
      kind: "all",
      onlyExisting: false,
      workspaces: [],
      homeDir: home,
    });
    expect(summary.items.length).toBe(0);
  });

  it("sorts items deterministically", () => {
    const summary = runInventory({
      scope: "all",
      kind: "all",
      onlyExisting: false,
      workspaces: [workspace],
      homeDir: home,
    });

    const tools = summary.items.map((i) => i.tool);
    const sorted = [...tools].sort((a, b) => a.localeCompare(b));
    // Weak check: first tool alphabetically should come first
    expect(tools[0]).toBe(sorted[0]);
  });
});

/**
 * The server decides whether an artifact's contents may be uploaded, and the
 * only honest basis for that is how the file is written: markdown and text are
 * prose, while jsonc, toml and dotenv hold configuration and therefore hold
 * credentials. That signal has to reach the wire for the server to use it.
 */
describe("inventory items carry a format", () => {
  let home: string;
  let workspace: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "codegate-fmt-home-"));
    workspace = mkdtempSync(join(tmpdir(), "codegate-fmt-ws-"));
  });

  afterEach(() => {
    for (const dir of [home, workspace]) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  });

  const inventory = () =>
    runInventory({
      scope: "all",
      kind: "all",
      onlyExisting: true,
      workspaces: [workspace],
      homeDir: home,
    });

  it("takes the declared format for a config entry", () => {
    mkdirSync(join(workspace, ".claude"), { recursive: true });
    writeFileSync(join(workspace, ".claude", "settings.json"), "{}\n");

    const item = inventory().items.find((i) => i.path.endsWith("settings.json"));
    expect(item?.format).toBe("jsonc");
  });

  it("derives a format for a skill, which the knowledge base does not declare", () => {
    mkdirSync(join(home, ".claude", "skills", "x"), { recursive: true });
    writeFileSync(join(home, ".claude", "skills", "x", "SKILL.md"), "x\n");

    const item = inventory().items.find((i) => i.kind === "skill" && i.path.endsWith("SKILL.md"));
    expect(item?.format).toBe("markdown");
  });

  it("marks prose as prose so a rules file can be told from a config", () => {
    writeFileSync(join(workspace, "CLAUDE.md"), "# r\n");

    const item = inventory().items.find((i) => i.path.endsWith("CLAUDE.md"));
    expect(item?.format).toBe("markdown");
  });
});
