import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());

function read(path: string): string {
  return readFileSync(resolve(root, path), "utf8");
}

describe("task 20 release contract", () => {
  it("uses semantic-release on main pushes with OIDC trusted publishing", () => {
    const workflow = read(".github/workflows/release.yml");
    expect(workflow).toContain("branches:");
    expect(workflow).toContain("- main");
    expect(workflow).toContain("id-token: write");
    expect(workflow).toContain("npx semantic-release");
    expect(workflow).not.toContain("registry-url:");
    expect(workflow).not.toContain("NPM_TOKEN");
    expect(workflow).not.toContain("NODE_AUTH_TOKEN");
    expect(workflow).not.toContain("tags:");
  });

  it("defines semantic version rules for commit types, including docs patch releases", () => {
    const releaseConfig = read(".releaserc.json");

    expect(releaseConfig).toContain('"@semantic-release/commit-analyzer"');
    expect(releaseConfig).toContain('"@semantic-release/exec"');
    expect(releaseConfig).toContain(
      '"prepareCmd": "npm version ${nextRelease.version} --no-git-tag-version"',
    );
    expect(releaseConfig).toContain('"publishCmd": "npm publish --provenance --access public"');
    expect(releaseConfig).not.toContain('"@semantic-release/npm"');
    expect(releaseConfig).toContain('"type": "feat"');
    expect(releaseConfig).toContain('"release": "minor"');
    expect(releaseConfig).toContain('"type": "docs"');
    expect(releaseConfig).toContain('"release": "patch"');
    expect(releaseConfig).toContain('"BREAKING CHANGE"');
  });
});
