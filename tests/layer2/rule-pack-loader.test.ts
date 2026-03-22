import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { loadRulePacks } from "../../src/layer2-static/rule-pack-loader";

function writePackFile(baseDir: string, fileName: string, rules: unknown): string {
  const path = resolve(baseDir, fileName);
  writeFileSync(path, JSON.stringify(rules, null, 2), "utf8");
  return path;
}

describe("task 08 rule pack loader", () => {
  it("loads bundled rules and external rule packs from configured paths", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-rule-pack-"));
    const externalPack = writePackFile(root, "custom.json", [
      {
        id: "custom-rule",
        severity: "low",
        category: "CUSTOM",
        description: "Custom rule",
        tool: "*",
        file_pattern: "README.md",
        query_type: "text_pattern",
        query: "custom",
        condition: "contains",
        owasp: ["ASI01"],
        cwe: "CWE-1036",
      },
    ]);

    const packs = loadRulePacks({ rule_pack_paths: [externalPack] });
    const ids = packs.map((rule) => rule.id);

    expect(ids).toContain("claude-mcp-consent-bypass");
    expect(ids).toContain("env-base-url-override");
    expect(ids).toContain("custom-rule");
  });

  it("keeps only allowed rules when allowed_rules is set", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-rule-allow-"));
    const packPath = writePackFile(root, "pack.json", [
      {
        id: "allowed-rule",
        severity: "low",
        category: "CUSTOM",
        description: "Allowed rule",
        tool: "*",
        file_pattern: "README.md",
        query_type: "text_pattern",
        query: "allowed",
        condition: "contains",
        owasp: ["ASI01"],
        cwe: "CWE-1036",
      },
      {
        id: "skipped-rule",
        severity: "low",
        category: "CUSTOM",
        description: "Skipped rule",
        tool: "*",
        file_pattern: "README.md",
        query_type: "text_pattern",
        query: "skipped",
        condition: "contains",
        owasp: ["ASI01"],
        cwe: "CWE-1036",
      },
    ]);

    const packs = loadRulePacks({
      rule_pack_paths: [packPath],
      allowed_rules: ["allowed-rule"],
    });

    expect(packs.map((rule) => rule.id)).toEqual(["allowed-rule"]);
  });

  it("skips rules listed in skip_rules after loading", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-rule-skip-"));
    const packPath = writePackFile(root, "pack.json", [
      {
        id: "kept-rule",
        severity: "low",
        category: "CUSTOM",
        description: "Kept rule",
        tool: "*",
        file_pattern: "README.md",
        query_type: "text_pattern",
        query: "kept",
        condition: "contains",
        owasp: ["ASI01"],
        cwe: "CWE-1036",
      },
      {
        id: "removed-rule",
        severity: "low",
        category: "CUSTOM",
        description: "Removed rule",
        tool: "*",
        file_pattern: "README.md",
        query_type: "text_pattern",
        query: "removed",
        condition: "contains",
        owasp: ["ASI01"],
        cwe: "CWE-1036",
      },
    ]);

    const packs = loadRulePacks({
      rule_pack_paths: [packPath],
      skip_rules: ["removed-rule"],
    });

    const ids = packs.map((rule) => rule.id);

    expect(ids).toContain("kept-rule");
    expect(ids).not.toContain("removed-rule");
  });

  it("uses a deterministic last-wins strategy for duplicate rule ids", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-rule-dup-"));
    const firstPack = writePackFile(root, "01-first.json", [
      {
        id: "duplicate-rule",
        severity: "low",
        category: "CUSTOM",
        description: "First rule",
        tool: "*",
        file_pattern: "README.md",
        query_type: "text_pattern",
        query: "first",
        condition: "contains",
        owasp: ["ASI01"],
        cwe: "CWE-1036",
      },
    ]);
    const secondPack = writePackFile(root, "02-second.json", [
      {
        id: "duplicate-rule",
        severity: "high",
        category: "CUSTOM",
        description: "Second rule",
        tool: "*",
        file_pattern: "README.md",
        query_type: "text_pattern",
        query: "second",
        condition: "contains",
        owasp: ["ASI01"],
        cwe: "CWE-1036",
      },
    ]);

    const packs = loadRulePacks({ rule_pack_paths: [firstPack, secondPack] });
    const duplicate = packs.find((rule) => rule.id === "duplicate-rule");

    expect(duplicate?.severity).toBe("high");
    expect(duplicate?.description).toBe("Second rule");
  });

  it("fails with a clear error when a rule pack contains invalid JSON", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-rule-json-"));
    const packPath = resolve(root, "broken.json");
    writeFileSync(packPath, "{", "utf8");

    expect(() => loadRulePacks({ rule_pack_paths: [packPath] })).toThrowError(/broken\.json/iu);
  });

  it("fails with a clear error when a rule pack entry does not match the schema", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-rule-schema-"));
    const packPath = writePackFile(root, "invalid.json", [
      {
        severity: "low",
        category: "CUSTOM",
        description: "Missing id",
        tool: "*",
        file_pattern: "README.md",
        query_type: "text_pattern",
        query: "missing",
        condition: "contains",
        owasp: ["ASI01"],
        cwe: "CWE-1036",
      },
    ]);

    expect(() => loadRulePacks({ rule_pack_paths: [packPath] })).toThrowError(/invalid\.json/iu);
  });
});
