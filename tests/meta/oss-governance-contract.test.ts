import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());

function read(path: string): string {
  return readFileSync(resolve(root, path), "utf8");
}

describe("task 03 open-source governance contract", () => {
  it("contains required top-level governance docs", () => {
    expect(existsSync(resolve(root, "README.md"))).toBe(true);
    expect(existsSync(resolve(root, "LICENSE"))).toBe(true);
    expect(existsSync(resolve(root, "CONTRIBUTING.md"))).toBe(true);
    expect(existsSync(resolve(root, "CODE_OF_CONDUCT.md"))).toBe(true);
    expect(existsSync(resolve(root, "SECURITY.md"))).toBe(true);
    expect(existsSync(resolve(root, "SUPPORT.md"))).toBe(true);
  });

  it("contains required GitHub templates", () => {
    expect(existsSync(resolve(root, ".github/ISSUE_TEMPLATE/bug_report.md"))).toBe(true);
    expect(existsSync(resolve(root, ".github/ISSUE_TEMPLATE/feature_request.md"))).toBe(true);
    expect(existsSync(resolve(root, ".github/pull_request_template.md"))).toBe(true);
  });

  it("documents contribution and vulnerability reporting entry points", () => {
    expect(read("README.md")).toContain("Contributing");
    expect(read("README.md")).toContain("Security");
    expect(read("SECURITY.md")).toContain("How to report a vulnerability");
    expect(read("CONTRIBUTING.md")).toContain("Development Workflow");
  });
});
