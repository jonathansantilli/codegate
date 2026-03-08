import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());

function read(path: string): string {
  return readFileSync(resolve(root, path), "utf8");
}

describe("task 04 ci workflow contract", () => {
  it("contains required workflow files", () => {
    expect(existsSync(resolve(root, ".github/workflows/ci.yml"))).toBe(true);
    expect(existsSync(resolve(root, ".github/workflows/release-dry-run.yml"))).toBe(true);
    expect(existsSync(resolve(root, ".github/workflows/semantic-pr-title.yml"))).toBe(true);
    expect(existsSync(resolve(root, ".github/workflows/codeql.yml"))).toBe(true);
  });

  it("runs verification checks across a platform matrix", () => {
    const ci = read(".github/workflows/ci.yml");
    expect(ci).toContain("permissions:");
    expect(ci).toContain("contents: read");
    expect(ci).toContain("concurrency:");
    expect(ci).toContain("ubuntu-latest");
    expect(ci).toContain("macos-latest");
    expect(ci).toContain("windows-latest");
    expect(ci).toContain("20.19.0");
    expect(ci).toContain("22.13.0");
    expect(ci).toContain("24.x");
    expect(ci).toContain("npm run lint");
    expect(ci).toContain("npm run typecheck");
    expect(ci).toContain("npm run test");
    expect(ci).toContain("npm run build");
  });

  it("contains a release dry-run workflow with semantic-release dry-run validation", () => {
    const workflow = read(".github/workflows/release-dry-run.yml");
    expect(workflow).toContain("workflow_dispatch");
    expect(workflow).toContain("npx semantic-release --dry-run");
    expect(workflow).not.toContain("NPM_TOKEN");
    expect(workflow).not.toContain("registry-url:");
  });

  it("configures dependabot with grouped npm and GitHub Actions updates", () => {
    const dependabot = read(".github/dependabot.yml");
    expect(dependabot).toContain('package-ecosystem: "npm"');
    expect(dependabot).toContain('package-ecosystem: "github-actions"');
    expect(dependabot).toContain("groups:");
    expect(dependabot).toContain("cooldown:");
    expect(dependabot).toContain("commit-message:");
  });

  it("contains a CodeQL workflow for JavaScript/TypeScript and GitHub Actions", () => {
    const workflow = read(".github/workflows/codeql.yml");
    expect(workflow).toContain("github/codeql-action/init");
    expect(workflow).toContain("github/codeql-action/analyze");
    expect(workflow).toContain("javascript-typescript");
    expect(workflow).toContain("actions");
    expect(workflow).toContain("security-extended");
  });

  it("pins semantic PR title action to an immutable commit SHA", () => {
    const workflow = read(".github/workflows/semantic-pr-title.yml");
    expect(workflow).toContain(
      "amannn/action-semantic-pull-request@48f256284bd46cdaab1048c3721360e808335d50",
    );
    expect(workflow).not.toContain("amannn/action-semantic-pull-request@v6");
  });
});
