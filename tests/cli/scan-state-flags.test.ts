import { describe, expect, it, vi } from "vitest";
import { createCli, type CliDeps } from "../../src/cli";
import type { CodeGateConfig } from "../../src/config";
import type { CodeGateReport } from "../../src/types/report";

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

const EMPTY_REPORT: CodeGateReport = {
  version: "0.1.0",
  scan_target: ".",
  timestamp: "2026-02-28T00:00:00.000Z",
  kb_version: "2026-02-28",
  tools_detected: [],
  findings: [],
  summary: {
    total: 0,
    by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    fixable: 0,
    suppressed: 0,
    exit_code: 0,
  },
};

function makeDeps(overrides: Partial<CliDeps>): CliDeps {
  return {
    cwd: () => process.cwd(),
    isTTY: () => false,
    resolveConfig: () => BASE_CONFIG,
    runScan: async () => EMPTY_REPORT,
    stdout: () => {},
    stderr: () => {},
    writeFile: () => {},
    setExitCode: () => {},
    ...overrides,
  };
}

describe("task 31 scan state cli flags", () => {
  it("resets scan state and exits without running scan", async () => {
    const resetScanState = vi.fn(async () => {});
    const runScan = vi.fn(async () => EMPTY_REPORT);
    let exitCode = -1;

    const cli = createCli(
      "0.1.0",
      makeDeps({
        resetScanState,
        runScan,
        setExitCode: (value) => {
          exitCode = value;
        },
      }),
    );

    await cli.parseAsync(["node", "codegate", "scan", ".", "--reset-state"]);
    expect(resetScanState).toHaveBeenCalledTimes(1);
    expect(runScan).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
  });

  it("returns exit 3 when reset-state operation fails", async () => {
    let exitCode = -1;
    const cli = createCli(
      "0.1.0",
      makeDeps({
        resetScanState: async () => {
          throw new Error("permission denied");
        },
        setExitCode: (value) => {
          exitCode = value;
        },
      }),
    );

    await cli.parseAsync(["node", "codegate", "scan", ".", "--reset-state"]);
    expect(exitCode).toBe(3);
  });

  it("passes configured scan-state path into reset operation", async () => {
    const resetScanState = vi.fn(async () => {});
    const cli = createCli(
      "0.1.0",
      makeDeps({
        resolveConfig: () => ({
          ...BASE_CONFIG,
          scan_state_path: "/tmp/custom-scan-state.json",
        }),
        resetScanState,
      }),
    );

    await cli.parseAsync(["node", "codegate", "scan", ".", "--reset-state"]);
    expect(resetScanState).toHaveBeenCalledWith("/tmp/custom-scan-state.json");
  });
});
