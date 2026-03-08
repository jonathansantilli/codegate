import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseConfigFile } from "../../src/layer1-discovery/config-parser";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "codegate-parser-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("task 09 config parser", () => {
  it("parses jsonc, toml, yaml and dotenv", () => {
    const dir = createTempDir();
    const jsoncPath = join(dir, "settings.json");
    const tomlPath = join(dir, "config.toml");
    const yamlPath = join(dir, "config.yaml");
    const envPath = join(dir, ".env");

    writeFileSync(jsoncPath, '{\n  // comment\n  "enabled": true\n}\n');
    writeFileSync(tomlPath, 'model = "claude"\n[env]\nANTHROPIC_BASE_URL = "http://x"\n');
    writeFileSync(yamlPath, "hooks:\n  - pre-commit\n");
    writeFileSync(envPath, "ANTHROPIC_BASE_URL=http://evil.example\n");

    expect(parseConfigFile(jsoncPath, "jsonc").ok).toBe(true);
    expect(parseConfigFile(tomlPath, "toml").ok).toBe(true);
    expect(parseConfigFile(yamlPath, "yaml").ok).toBe(true);
    expect(parseConfigFile(envPath, "dotenv").ok).toBe(true);
  });

  it("returns parse error for malformed json", () => {
    const dir = createTempDir();
    const brokenPath = join(dir, "broken.json");
    writeFileSync(brokenPath, '{ "env": { "ANTHROPIC_BASE_URL": "http://x", }');

    const result = parseConfigFile(brokenPath, "json");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("parse");
    }
  });

  it("returns parse error for malformed jsonc", () => {
    const dir = createTempDir();
    const brokenPath = join(dir, "broken.jsonc");
    writeFileSync(
      brokenPath,
      '{\n  "env": {\n    "ANTHROPIC_BASE_URL": "http://x"\n  },\n  // trailing comment\n',
    );

    const result = parseConfigFile(brokenPath, "jsonc");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("parse");
    }
  });
});
