import { describe, expect, it, vi } from "vitest";
import { createCli } from "../../src/cli";
import { executeWrapperRun, type WrapperDeps } from "../../src/wrapper";
import type { CodeGateConfig } from "../../src/config";
import type { CodeGateReport } from "../../src/types/report";

const BASE_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: true,
  output_format: "terminal",
  tui: { enabled: true, colour_scheme: "default", compact_mode: false },
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

function makeReport(exitCode: number): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-02-28T00:00:00.000Z",
    kb_version: "2026-02-28",
    tools_detected: ["claude-code"],
    findings: [],
    summary: {
      total: 0,
      by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      fixable: 0,
      suppressed: 0,
      exit_code: exitCode,
    },
  };
}

function makeWarningReport(): CodeGateReport {
  return {
    ...makeReport(1),
    findings: [
      {
        rule_id: "rule-file-long-line",
        finding_id: "RULE_INJECTION-AGENTS.md-long_line",
        severity: "LOW",
        category: "RULE_INJECTION",
        layer: "L2",
        file_path: "AGENTS.md",
        location: { field: "long_line" },
        description: "Rule file contains unusually long lines that may hide payloads",
        affected_tools: ["codex-cli"],
        cve: null,
        owasp: ["ASI01"],
        cwe: "CWE-116",
        confidence: "HIGH",
        fixable: true,
        remediation_actions: ["strip_unicode"],
        suppressed: false,
      },
    ],
    summary: {
      total: 1,
      by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1, INFO: 0 },
      fixable: 1,
      suppressed: 0,
      exit_code: 1,
    },
  };
}

function createWrapperDeps(overrides: Partial<WrapperDeps>): WrapperDeps {
  return {
    runScan: async () => makeReport(0),
    detectTools: () => [],
    launchTool: () => ({ status: 0 }),
    collectScanSurface: () => ["/tmp/project/.mcp.json"],
    captureSnapshot: () => new Map([["a", "1"]]),
    stdout: () => {},
    stderr: () => {},
    setExitCode: () => {},
    ...overrides,
  };
}

describe("task 17 run command wrapper", () => {
  it("returns exit 3 for unknown tool target", async () => {
    let exitCode = -1;
    const stderr = vi.fn();

    await executeWrapperRun(
      {
        target: "unknown-tool",
        cwd: process.cwd(),
        version: "0.1.0",
        config: BASE_CONFIG,
      },
      createWrapperDeps({
        stderr,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(exitCode).toBe(3);
    expect(stderr).toHaveBeenCalledWith(
      "Unknown tool: unknown-tool. Valid targets: claude, opencode, codex, cursor, windsurf, kiro.",
    );
  });

  it("returns exit 3 when tool is recognised but not installed", async () => {
    let exitCode = -1;
    const stderr = vi.fn();

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: BASE_CONFIG,
      },
      createWrapperDeps({
        detectTools: () => [{ tool: "claude-code", installed: false, version: null, path: null, source: "none" }],
        stderr,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(exitCode).toBe(3);
    expect(stderr).toHaveBeenCalledWith("claude is not installed.");
  });

  it("returns exit 3 when files change between scan and launch", async () => {
    let exitCode = -1;
    const launch = vi.fn(() => ({ status: 0 }));
    const stderr = vi.fn();
    let snapshots = 0;

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: BASE_CONFIG,
      },
      createWrapperDeps({
        detectTools: () => [
          { tool: "claude-code", installed: true, version: "1.0.0", path: "/usr/bin/claude", source: "path" },
        ],
        captureSnapshot: () => {
          snapshots += 1;
          return snapshots === 1 ? new Map([["a", "1"]]) : new Map([["a", "2"]]);
        },
        launchTool: launch,
        stderr,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(exitCode).toBe(3);
    expect(launch).not.toHaveBeenCalled();
    expect(stderr).toHaveBeenCalledWith("Config files changed after scan. Re-run `codegate scan` before launch.");
  });

  it("returns exit 3 when files change during scan execution", async () => {
    let exitCode = -1;
    const launch = vi.fn(() => ({ status: 0 }));
    const stderr = vi.fn();
    let mutated = false;

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: BASE_CONFIG,
      },
      createWrapperDeps({
        detectTools: () => [
          { tool: "claude-code", installed: true, version: "1.0.0", path: "/usr/bin/claude", source: "path" },
        ],
        runScan: async () => {
          mutated = true;
          return makeReport(0);
        },
        captureSnapshot: () => new Map([[".mcp.json", mutated ? "changed" : "original"]]),
        launchTool: launch,
        stderr,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(exitCode).toBe(3);
    expect(launch).not.toHaveBeenCalled();
    expect(stderr).toHaveBeenCalledWith("Config files changed after scan. Re-run `codegate scan` before launch.");
  });

  it("falls back to manual guidance for GUI tools without CLI launcher", async () => {
    let exitCode = -1;
    const stdout = vi.fn();
    const launch = vi.fn(() => ({ status: 0 }));

    await executeWrapperRun(
      {
        target: "cursor",
        cwd: process.cwd(),
        version: "0.1.0",
        config: BASE_CONFIG,
      },
      createWrapperDeps({
        detectTools: () => [
          {
            tool: "cursor",
            installed: true,
            version: "0.50.1",
            path: "/Applications/Cursor.app",
            source: "app-bundle",
          },
        ],
        stdout,
        launchTool: launch,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(exitCode).toBe(0);
    expect(launch).not.toHaveBeenCalled();
    expect(stdout).toHaveBeenCalledWith(
      "Scan complete. cursor appears installed without a CLI launcher. Launch it manually.",
    );
  });

  it("does not silently launch when warnings exist and auto-proceed is disabled", async () => {
    let exitCode = -1;
    const launch = vi.fn(() => ({ status: 0 }));

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: {
          ...BASE_CONFIG,
          auto_proceed_below_threshold: false,
        },
      },
      createWrapperDeps({
        detectTools: () => [
          { tool: "claude-code", installed: true, version: "1.0.0", path: "/usr/bin/claude", source: "path" },
        ],
        runScan: async () => makeWarningReport(),
        launchTool: launch,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(exitCode).toBe(1);
    expect(launch).not.toHaveBeenCalled();
  });

  it("uses the discovered scan surface for snapshot checks", async () => {
    const captureSnapshot = vi.fn(() => new Map([["a", "1"]]));
    const surface = [
      "/tmp/project/.mcp.json",
      "/Users/tester/.codex/config.toml",
    ];

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: BASE_CONFIG,
      },
      {
        ...createWrapperDeps({
          detectTools: () => [
            { tool: "claude-code", installed: true, version: "1.0.0", path: "/usr/bin/claude", source: "path" },
          ],
          captureSnapshot: captureSnapshot as unknown as WrapperDeps["captureSnapshot"],
        }),
        collectScanSurface: async () => surface,
      } as WrapperDeps,
    );

    expect(captureSnapshot).toHaveBeenCalledWith(surface);
  });

  it("recollects the scan surface so newly introduced config files block launch", async () => {
    let exitCode = -1;
    const launch = vi.fn(() => ({ status: 0 }));
    const collectScanSurface = vi
      .fn<WrapperDeps["collectScanSurface"]>()
      .mockResolvedValueOnce(["/tmp/project/.mcp.json"])
      .mockResolvedValueOnce(["/tmp/project/.mcp.json", "/tmp/project/.cursor/mcp.json"]);
    const captureSnapshot = vi.fn((paths: string[]) => new Map(paths.map((path) => [path, path])));

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: BASE_CONFIG,
      },
      createWrapperDeps({
        detectTools: () => [
          { tool: "claude-code", installed: true, version: "1.0.0", path: "/usr/bin/claude", source: "path" },
        ],
        collectScanSurface,
        captureSnapshot: captureSnapshot as unknown as WrapperDeps["captureSnapshot"],
        launchTool: launch,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(collectScanSurface).toHaveBeenCalledTimes(2);
    expect(launch).not.toHaveBeenCalled();
    expect(exitCode).toBe(3);
  });

  it("launches warning-only reports when force bypass is enabled", async () => {
    let exitCode = -1;
    const launch = vi.fn(() => ({ status: 0 }));

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: {
          ...BASE_CONFIG,
          auto_proceed_below_threshold: false,
        },
        force: true,
      },
      createWrapperDeps({
        detectTools: () => [
          { tool: "claude-code", installed: true, version: "1.0.0", path: "/usr/bin/claude", source: "path" },
        ],
        runScan: async () => makeWarningReport(),
        launchTool: launch,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(exitCode).toBe(1);
    expect(launch).toHaveBeenCalledTimes(1);
  });

  it("launches warning-only reports inside trusted directories without prompting", async () => {
    let exitCode = -1;
    const launch = vi.fn(() => ({ status: 0 }));

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: {
          ...BASE_CONFIG,
          auto_proceed_below_threshold: false,
          trusted_directories: [process.cwd()],
        },
      },
      createWrapperDeps({
        detectTools: () => [
          { tool: "claude-code", installed: true, version: "1.0.0", path: "/usr/bin/claude", source: "path" },
        ],
        runScan: async () => makeWarningReport(),
        launchTool: launch,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(exitCode).toBe(1);
    expect(launch).toHaveBeenCalledTimes(1);
  });

  it("launches warning-only reports after explicit confirmation", async () => {
    let exitCode = -1;
    const launch = vi.fn(() => ({ status: 0 }));
    const requestWarningProceed = vi.fn(async () => true);

    await executeWrapperRun(
      {
        target: "claude",
        cwd: process.cwd(),
        version: "0.1.0",
        config: {
          ...BASE_CONFIG,
          auto_proceed_below_threshold: false,
        },
        requestWarningProceed,
      },
      createWrapperDeps({
        detectTools: () => [
          { tool: "claude-code", installed: true, version: "1.0.0", path: "/usr/bin/claude", source: "path" },
        ],
        runScan: async () => makeWarningReport(),
        launchTool: launch,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(requestWarningProceed).toHaveBeenCalledTimes(1);
    expect(exitCode).toBe(1);
    expect(launch).toHaveBeenCalledTimes(1);
  });

  it("wires cli run subcommand to wrapper execution", async () => {
    const runWrapper = vi.fn(async () => {});
    let exitCode = -1;

    const cli = createCli("0.1.0", {
      cwd: () => process.cwd(),
      isTTY: () => false,
      resolveConfig: () => BASE_CONFIG,
      runScan: async () => makeReport(0),
      stdout: () => {},
      stderr: () => {},
      writeFile: () => {},
      setExitCode: (code) => {
        exitCode = code;
      },
      runWrapper,
    });

    await cli.parseAsync(["node", "codegate", "run", "claude"]);
    expect(runWrapper).toHaveBeenCalledTimes(1);
    expect(exitCode).toBe(-1);
  });

  it("does not wire warning prompts when run --no-tui is passed", async () => {
    const runWrapper = vi.fn(async () => {});

    const cli = createCli("0.1.0", {
      cwd: () => process.cwd(),
      isTTY: () => true,
      resolveConfig: () => ({
        ...BASE_CONFIG,
        auto_proceed_below_threshold: false,
      }),
      runScan: async () => makeReport(0),
      stdout: () => {},
      stderr: () => {},
      writeFile: () => {},
      setExitCode: () => {},
      runWrapper,
      requestRunWarningConsent: vi.fn(async () => true),
    });

    await cli.parseAsync(["node", "codegate", "run", "claude", "--no-tui"]);

    expect(runWrapper).toHaveBeenCalledWith(
      expect.objectContaining({
        requestWarningProceed: undefined,
      }),
    );
  });
});
