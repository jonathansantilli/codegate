import { describe, expect, it, vi } from "vitest";
import { executeScanCommand } from "../../src/commands/scan-command";
import type { CodeGateConfig } from "../../src/config";
import type { ScanDiscoveryContext } from "../../src/scan";
import type { CodeGateReport } from "../../src/types/report";

const BASE_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: true,
  output_format: "terminal",
  scan_state_path: "/tmp/codegate-scan-state.json",
  scan_user_scope: true,
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

function emptyReport(): CodeGateReport {
  return {
    version: "0.2.2",
    scan_target: ".",
    timestamp: "2026-03-06T00:00:00.000Z",
    kb_version: "2026-03-06",
    tools_detected: ["claude-code"],
    findings: [],
    summary: {
      total: 0,
      by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      fixable: 0,
      suppressed: 0,
      exit_code: 0,
    },
  };
}

describe("scan command service", () => {
  it("reuses prepared discovery context across scan and deep resource discovery", async () => {
    const discoveryContext = { tag: "prepared-context" } as unknown as ScanDiscoveryContext;
    const prepareScanDiscovery = vi.fn(() => discoveryContext);
    const runScan = vi.fn(async (input: { discoveryContext?: unknown }) => {
      expect(input.discoveryContext).toBe(discoveryContext);
      return emptyReport();
    });
    const discoverDeepResources = vi.fn(
      async (_scanTarget: string, _config: CodeGateConfig, context?: unknown) => {
        expect(context).toBe(discoveryContext);
        return [];
      },
    );

    const stdout: string[] = [];
    let exitCode = -1;

    await executeScanCommand(
      {
        version: "0.2.2",
        cwd: process.cwd(),
        scanTarget: process.cwd(),
        config: BASE_CONFIG,
        options: { deep: true },
      },
      {
        isTTY: () => false,
        prepareScanDiscovery,
        runScan: runScan as never,
        discoverDeepResources,
        stdout: (message) => {
          stdout.push(message);
        },
        stderr: () => {},
        writeFile: () => {},
        setExitCode: (code) => {
          exitCode = code;
        },
      },
    );

    expect(prepareScanDiscovery).toHaveBeenCalledTimes(1);
    expect(runScan).toHaveBeenCalledTimes(1);
    expect(discoverDeepResources).toHaveBeenCalledTimes(1);
    expect(stdout.some((line) => line.includes("Deep scan skipped"))).toBe(true);
    expect(exitCode).toBe(0);
  });
});
