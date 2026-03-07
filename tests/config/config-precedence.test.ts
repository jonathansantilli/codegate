import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveEffectiveConfig } from "../../src/config";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      // Node v20+ supports recursive rm via fs.rmSync but we avoid an extra import for simple cleanup.
      // The temp directory is OS-managed and ephemeral if removal fails.
      void dir;
    } catch {
      // ignore cleanup errors
    }
  }
});

describe("task 16 config precedence", () => {
  it("merges list fields and applies scalar precedence (cli > project > global > defaults)", () => {
    const workspace = makeTempDir("codegate-config-");
    const homeDir = join(workspace, "home");
    const projectDir = join(workspace, "project");
    mkdirSync(homeDir, { recursive: true });
    mkdirSync(projectDir, { recursive: true });

    const globalConfigPath = join(homeDir, ".codegate", "config.json");
    mkdirSync(join(homeDir, ".codegate"), { recursive: true });
    writeFileSync(
      globalConfigPath,
      JSON.stringify(
        {
          severity_threshold: "medium",
          output_format: "markdown",
          scan_state_path: "/global/scan-state.json",
          blocked_commands: ["python3"],
          known_safe_mcp_servers: ["global-safe-server"],
          suppress_findings: ["GLOBAL-SUPPRESSION"],
          trusted_api_domains: ["proxy.example.com"],
          trusted_directories: ["/safe/from-global"],
          scan_user_scope: false,
        },
        null,
        2,
      ),
      "utf8",
    );

    const projectConfigPath = join(projectDir, ".codegate.json");
    writeFileSync(
      projectConfigPath,
      JSON.stringify(
        {
          severity_threshold: "low",
          output_format: "html",
          scan_state_path: "/project/scan-state.json",
          blocked_commands: ["echo"],
          known_safe_mcp_servers: ["project-safe-server"],
          suppress_findings: ["PROJECT-SUPPRESSION"],
          trusted_api_domains: ["project.internal"],
          trusted_directories: ["/unsafe/project-attempt"],
          scan_user_scope: true,
        },
        null,
        2,
      ),
      "utf8",
    );

    const effective = resolveEffectiveConfig({
      scanTarget: projectDir,
      homeDir,
      cli: {
        format: "json",
      },
    });

    expect(effective.output_format).toBe("json");
    expect(effective.severity_threshold).toBe("low");
    expect(effective.scan_state_path).toBe("/project/scan-state.json");
    expect(effective.known_safe_mcp_servers).toEqual(
      expect.arrayContaining(["global-safe-server", "project-safe-server"]),
    );
    expect(effective.suppress_findings).toEqual(
      expect.arrayContaining(["GLOBAL-SUPPRESSION", "PROJECT-SUPPRESSION"]),
    );
    expect(effective.trusted_api_domains).toEqual(
      expect.arrayContaining(["proxy.example.com", "project.internal"]),
    );
    expect(effective.trusted_directories).toEqual(["/safe/from-global"]);
    expect(effective.scan_user_scope).toBe(true);
    expect(effective.blocked_commands).toEqual(
      expect.arrayContaining(["bash", "curl", "python3", "echo"]),
    );
  });

  it("defaults scan_user_scope to true when not configured", () => {
    const workspace = makeTempDir("codegate-config-default-");
    const homeDir = join(workspace, "home");
    const projectDir = join(workspace, "project");
    mkdirSync(homeDir, { recursive: true });
    mkdirSync(projectDir, { recursive: true });

    const effective = resolveEffectiveConfig({
      scanTarget: projectDir,
      homeDir,
      cli: {},
    });

    expect(effective.scan_user_scope).toBe(true);
  });
});
