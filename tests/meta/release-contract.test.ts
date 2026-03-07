import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());

function read(path: string): string {
  return readFileSync(resolve(root, path), "utf8");
}

describe("task 20 release contract", () => {
  it("contains release workflow and changelog; validates private checklists when present", () => {
    expect(existsSync(resolve(root, ".github/workflows/release.yml"))).toBe(true);
    expect(existsSync(resolve(root, "CHANGELOG.md"))).toBe(true);

    const hasPrivateReleaseDocs =
      existsSync(resolve(root, "docs/release/v1.0-checklist.md")) || existsSync(resolve(root, "docs/deep-scan.md"));
    if (!hasPrivateReleaseDocs) {
      expect(true).toBe(true);
      return;
    }

    expect(existsSync(resolve(root, "docs/release/v1.0-checklist.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/release/v2.0-checklist.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/release/v2.2-addendum-checklist.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/deep-scan.md"))).toBe(true);
  });

  it("publishes to npm with provenance in release workflow", () => {
    const workflow = read(".github/workflows/release.yml");
    expect(workflow).toContain("NPM_TOKEN");
    expect(workflow).toContain("npm publish --access public --provenance");
  });
});
