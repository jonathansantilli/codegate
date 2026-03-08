import { describe, expect, it, vi } from "vitest";
import { createCli } from "../../src/cli";
import type { CodeGateConfig } from "../../src/config";

const BASE_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: true,
  output_format: "terminal",
  tui: { enabled: false, colour_scheme: "default", compact_mode: false },
  tool_discovery: { preferred_agent: "claude", agent_paths: {}, skip_tools: [] },
  trusted_directories: [],
  blocked_commands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
  known_safe_mcp_servers: [],
  known_safe_formatters: [],
  known_safe_lsp_servers: [],
  known_safe_hooks: [],
  unicode_analysis: true,
  check_ide_settings: true,
  owasp_mapping: true,
  trusted_api_domains: [],
  suppress_findings: [],
};

describe("undo command", () => {
  it("runs undo and reports restored session", async () => {
    let exitCode = -1;
    const stdout = vi.fn();
    const runUndo = vi.fn(() => ({ restoredFiles: 2, sessionId: "session-a" }));

    const cli = createCli("0.1.0", {
      cwd: () => process.cwd(),
      isTTY: () => false,
      resolveConfig: () => BASE_CONFIG,
      runScan: async () => {
        throw new Error("unused");
      },
      stdout,
      stderr: () => {},
      writeFile: () => {},
      setExitCode: (code) => {
        exitCode = code;
      },
      runUndo,
    });

    await cli.parseAsync(["node", "codegate", "undo"]);
    expect(runUndo).toHaveBeenCalledTimes(1);
    expect(exitCode).toBe(0);
    expect(stdout).toHaveBeenCalledWith("Restored 2 file(s) from backup session session-a.");
  });

  it("returns exit code 3 when undo fails", async () => {
    let exitCode = -1;
    const stderr = vi.fn();
    const runUndo = vi.fn(() => {
      throw new Error("No backup sessions found.");
    });

    const cli = createCli("0.1.0", {
      cwd: () => process.cwd(),
      isTTY: () => false,
      resolveConfig: () => BASE_CONFIG,
      runScan: async () => {
        throw new Error("unused");
      },
      stdout: () => {},
      stderr,
      writeFile: () => {},
      setExitCode: (code) => {
        exitCode = code;
      },
      runUndo,
    });

    await cli.parseAsync(["node", "codegate", "undo"]);
    expect(exitCode).toBe(3);
    expect(stderr).toHaveBeenCalledWith("Undo failed: No backup sessions found.");
  });
});
