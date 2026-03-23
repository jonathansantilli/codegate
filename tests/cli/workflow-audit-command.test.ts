import { describe, expect, it } from "vitest";
import { createCli, type CliDeps } from "../../src/cli";
import type { CodeGateReport } from "../../src/types/report";

const EMPTY_REPORT: CodeGateReport = {
  version: "0.1.0",
  scan_target: ".",
  timestamp: "2026-03-23T00:00:00.000Z",
  kb_version: "2026-03-23",
  tools_detected: ["github-actions"],
  findings: [],
  summary: {
    total: 0,
    by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    fixable: 0,
    suppressed: 0,
    exit_code: 0,
  },
};

function buildDeps(overrides: Partial<CliDeps> = {}): CliDeps {
  return {
    cwd: () => process.cwd(),
    isTTY: () => false,
    resolveConfig: () => ({
      severity_threshold: "high",
      auto_proceed_below_threshold: true,
      output_format: "terminal",
      scan_user_scope: false,
      strict_collection: false,
      scan_collection_modes: ["default"],
      persona: "regular",
      runtime_mode: "offline",
      workflow_audits: { enabled: false },
      tui: { enabled: false, colour_scheme: "default", compact_mode: false },
      tool_discovery: { preferred_agent: "claude", agent_paths: {}, skip_tools: [] },
      trusted_directories: [],
      blocked_commands: ["bash", "sh"],
      known_safe_mcp_servers: [],
      known_safe_formatters: [],
      known_safe_lsp_servers: [],
      known_safe_hooks: [],
      unicode_analysis: true,
      check_ide_settings: true,
      owasp_mapping: true,
      trusted_api_domains: [],
      suppress_findings: [],
      suppression_rules: [],
    }),
    runScan: async () => EMPTY_REPORT,
    stdout: () => {},
    stderr: () => {},
    writeFile: () => {},
    setExitCode: () => {},
    ...overrides,
  };
}

describe("workflow audit cli options", () => {
  it("forwards workflow audit scan options into config", async () => {
    let captured: CliDeps extends { runScan: (input: infer T) => Promise<unknown> } ? T : never;

    const deps = buildDeps({
      runScan: async (input) => {
        captured = input as typeof captured;
        return EMPTY_REPORT;
      },
    });

    const cli = createCli("0.1.0", deps);
    await cli.parseAsync([
      "node",
      "codegate",
      "scan",
      ".",
      "--workflow-audits",
      "--collect",
      "project",
      "--persona",
      "auditor",
      "--runtime-mode",
      "online",
    ]);

    expect(captured?.config.workflow_audits?.enabled).toBe(true);
    expect(captured?.config.scan_collection_modes).toEqual(["project"]);
    expect(captured?.config.persona).toBe("auditor");
    expect(captured?.config.runtime_mode).toBe("online");
  });
});
