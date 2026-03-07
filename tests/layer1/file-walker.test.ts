import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { walkProjectTree } from "../../src/layer1-discovery/file-walker";
import { normalizeSlashes } from "../helpers/path";

const tempDirs: string[] = [];

function createProjectTree(): string {
  const root = join(tmpdir(), `codegate-walk-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  mkdirSync(root, { recursive: true });
  tempDirs.push(root);
  return root;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("task 09 file walker", () => {
  it("skips noisy directories and includes .git/hooks", () => {
    const root = createProjectTree();
    mkdirSync(join(root, "node_modules/pkg"), { recursive: true });
    mkdirSync(join(root, ".git/hooks"), { recursive: true });
    writeFileSync(join(root, "node_modules/pkg/index.js"), "ignored");
    writeFileSync(join(root, ".git/hooks/pre-commit"), "#!/bin/sh\necho hi");
    writeFileSync(join(root, "README.md"), "ok");

    const result = walkProjectTree(root);
    const files = result.files.map(normalizeSlashes);
    expect(files.some((file) => file.endsWith("README.md"))).toBe(true);
    expect(files.some((file) => file.includes("node_modules"))).toBe(false);
    expect(files.some((file) => file.includes(".git/hooks/pre-commit"))).toBe(true);
  });

  it("detects symlink escape outside project root", () => {
    const root = createProjectTree();
    const outside = join(tmpdir(), "codegate-outside-target");
    writeFileSync(outside, "secret");
    symlinkSync(outside, join(root, "escape-link"));

    const result = walkProjectTree(root);
    expect(result.symlinkEscapes.length).toBe(1);
    expect(result.symlinkEscapes[0]?.path.endsWith("escape-link")).toBe(true);
  });
});
