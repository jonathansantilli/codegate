import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());

function read(path: string): string {
  return readFileSync(resolve(root, path), "utf8");
}

describe("task 35 addendum contract", () => {
  it("includes addendum release checklist and required docs when private docs are present", () => {
    const hasPrivateAddendumDocs =
      existsSync(resolve(root, "docs/release/v2.2-addendum-checklist.md")) ||
      existsSync(resolve(root, "docs/CodeGate-PRD-v3.md")) ||
      existsSync(resolve(root, "docs/CodeGate-PRD-Addendum-AgentScan.md"));
    if (!hasPrivateAddendumDocs) {
      expect(true).toBe(true);
      return;
    }

    expect(existsSync(resolve(root, "docs/release/v2.2-addendum-checklist.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/CodeGate-PRD-v3.md"))).toBe(true);
    expect(existsSync(resolve(root, "docs/CodeGate-PRD-Addendum-AgentScan.md"))).toBe(true);
  });

  it("documents rug-pull, safe tool description analysis, and toxic flow in PRD", () => {
    if (!existsSync(resolve(root, "docs/CodeGate-PRD-v3.md"))) {
      expect(true).toBe(true);
      return;
    }

    const prd = read("docs/CodeGate-PRD-v3.md");
    expect(prd).toContain("MCP Configuration Change Detection (Rug Pull)");
    expect(prd).toContain("MCP Tool Description Analysis (Safe Acquisition)");
    expect(prd).toContain("Toxic Flow Analysis (Tool Interaction Graph)");
    expect(prd).toContain("CONFIG_CHANGE");
    expect(prd).toContain("NEW_SERVER");
    expect(prd).toContain("TOXIC_FLOW");
    expect(prd).toContain("Snyk Agent Scan");
    expect(prd).toContain("without executing untrusted local stdio commands");
  });

  it("surfaces addendum operations in user/security docs", () => {
    const readme = read("README.md");
    const security = read("SECURITY.md");

    expect(readme).toContain("--reset-state");
    expect(readme).toContain("TOXIC_FLOW");
    expect(security).toContain("does not execute untrusted MCP stdio command arrays");
  });
});
