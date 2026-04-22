import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_CONFIG,
  LAYER3_REMOTE_FETCH_MAX_BYTES_ENV,
  LAYER3_REMOTE_FETCH_TIMEOUT_ENV,
  resolveEffectiveConfig,
} from "../../src/config";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  delete process.env[LAYER3_REMOTE_FETCH_TIMEOUT_ENV];
  delete process.env[LAYER3_REMOTE_FETCH_MAX_BYTES_ENV];
  tempDirs.splice(0);
});

describe("layer3 remote fetch limits config", () => {
  it("defaults to 5000ms / 1 MiB", () => {
    const home = makeTempDir("codegate-l3-defaults-home-");
    const project = makeTempDir("codegate-l3-defaults-project-");
    const resolved = resolveEffectiveConfig({ scanTarget: project, homeDir: home });
    expect(resolved.layer3_remote_fetch_timeout_ms).toBe(5000);
    expect(resolved.layer3_remote_fetch_max_bytes).toBe(1_048_576);
    expect(DEFAULT_CONFIG.layer3_remote_fetch_timeout_ms).toBe(5000);
    expect(DEFAULT_CONFIG.layer3_remote_fetch_max_bytes).toBe(1_048_576);
  });

  it("honours project config > global config > defaults", () => {
    const home = makeTempDir("codegate-l3-files-home-");
    const project = makeTempDir("codegate-l3-files-project-");
    mkdirSync(join(home, ".codegate"), { recursive: true });
    writeFileSync(
      join(home, ".codegate", "config.json"),
      JSON.stringify({
        layer3_remote_fetch_timeout_ms: 7000,
        layer3_remote_fetch_max_bytes: 2048,
      }),
      "utf8",
    );
    writeFileSync(
      join(project, ".codegate.json"),
      JSON.stringify({ layer3_remote_fetch_timeout_ms: 2500 }),
      "utf8",
    );

    const resolved = resolveEffectiveConfig({ scanTarget: project, homeDir: home });
    // Project override wins on timeout.
    expect(resolved.layer3_remote_fetch_timeout_ms).toBe(2500);
    // No project override on max_bytes => global value applies.
    expect(resolved.layer3_remote_fetch_max_bytes).toBe(2048);
  });

  it("env var takes precedence over project and global config", () => {
    const home = makeTempDir("codegate-l3-env-home-");
    const project = makeTempDir("codegate-l3-env-project-");
    mkdirSync(join(home, ".codegate"), { recursive: true });
    writeFileSync(
      join(home, ".codegate", "config.json"),
      JSON.stringify({
        layer3_remote_fetch_timeout_ms: 4000,
        layer3_remote_fetch_max_bytes: 2048,
      }),
      "utf8",
    );
    writeFileSync(
      join(project, ".codegate.json"),
      JSON.stringify({
        layer3_remote_fetch_timeout_ms: 3000,
        layer3_remote_fetch_max_bytes: 4096,
      }),
      "utf8",
    );

    process.env[LAYER3_REMOTE_FETCH_TIMEOUT_ENV] = "1500";
    process.env[LAYER3_REMOTE_FETCH_MAX_BYTES_ENV] = "16384";

    const resolved = resolveEffectiveConfig({ scanTarget: project, homeDir: home });
    expect(resolved.layer3_remote_fetch_timeout_ms).toBe(1500);
    expect(resolved.layer3_remote_fetch_max_bytes).toBe(16384);
  });

  it("ignores invalid env var values and falls back to config/defaults", () => {
    const home = makeTempDir("codegate-l3-bad-env-home-");
    const project = makeTempDir("codegate-l3-bad-env-project-");
    process.env[LAYER3_REMOTE_FETCH_TIMEOUT_ENV] = "not-a-number";
    process.env[LAYER3_REMOTE_FETCH_MAX_BYTES_ENV] = "-42";

    const resolved = resolveEffectiveConfig({ scanTarget: project, homeDir: home });
    expect(resolved.layer3_remote_fetch_timeout_ms).toBe(5000);
    expect(resolved.layer3_remote_fetch_max_bytes).toBe(1_048_576);
  });
});
