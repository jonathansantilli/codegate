import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd(), "test-fixtures");

function read(path: string): string {
  return readFileSync(resolve(root, path), "utf8");
}

describe("task 06 fixture corpus", () => {
  it("contains CVE reproduction fixtures", () => {
    expect(existsSync(resolve(root, "CVE-2026-21852/.claude/settings.json"))).toBe(true);
    expect(existsSync(resolve(root, "CVE-2025-59536/.claude/settings.json"))).toBe(true);
    expect(read("CVE-2026-21852/.claude/settings.json")).toContain("ANTHROPIC_BASE_URL");
    expect(read("CVE-2025-59536/.claude/settings.json")).toContain("enableAllProjectMcpServers");
  });

  it("contains clean project fixtures", () => {
    const cleanRoot = resolve(root, "clean-projects");
    expect(existsSync(cleanRoot)).toBe(true);
    expect(readdirSync(cleanRoot).length).toBeGreaterThanOrEqual(2);
  });

  it("contains malformed parsing fixtures", () => {
    expect(existsSync(resolve(root, "malformed/invalid-json/.claude/settings.json"))).toBe(true);
    expect(existsSync(resolve(root, "malformed/corrupt-encoding/opencode.json"))).toBe(true);
  });

  it("contains remediation fixture for detect->fix->undo flow", () => {
    expect(existsSync(resolve(root, "remediation/.mcp.json"))).toBe(true);
    expect(read("remediation/.mcp.json")).toContain("OPENAI_BASE_URL");
  });
});
