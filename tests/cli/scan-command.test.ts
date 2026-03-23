import { describe, expect, it } from "vitest";
import { createCli, type CliDeps } from "../../src/cli";
import { DEFAULT_CONFIG } from "../../src/config";
import type { Finding } from "../../src/types/finding";
import type { CodeGateReport } from "../../src/types/report";

function makeReport(findings: Finding[]): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-02-28T00:00:00.000Z",
    kb_version: "2026-02-28",
    tools_detected: ["claude-code"],
    findings,
    summary: {
      total: findings.length,
      by_severity: {
        CRITICAL: findings.filter((finding) => finding.severity === "CRITICAL").length,
        HIGH: findings.filter((finding) => finding.severity === "HIGH").length,
        MEDIUM: findings.filter((finding) => finding.severity === "MEDIUM").length,
        LOW: findings.filter((finding) => finding.severity === "LOW").length,
        INFO: findings.filter((finding) => finding.severity === "INFO").length,
      },
      fixable: findings.filter((finding) => finding.fixable).length,
      suppressed: findings.filter((finding) => finding.suppressed).length,
      exit_code: 0,
    },
  };
}

function makeFinding(severity: Finding["severity"]): Finding {
  return {
    rule_id: "test-rule",
    finding_id: `TEST-${severity}`,
    severity,
    category: "COMMAND_EXEC",
    layer: "L2",
    file_path: ".mcp.json",
    location: { field: "mcpServers.bad.command" },
    description: "Test finding",
    affected_tools: ["claude-code"],
    cve: null,
    owasp: ["ASI05"],
    cwe: "CWE-78",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field"],
    suppressed: false,
  };
}

function buildDeps(overrides: Partial<CliDeps>): CliDeps {
  const output: string[] = [];

  return {
    cwd: () => process.cwd(),
    isTTY: () => false,
    resolveConfig: () => ({
      severity_threshold: "high",
      auto_proceed_below_threshold: true,
      output_format: "terminal",
      scan_user_scope: false,
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
      strict_collection: false,
      scan_collection_modes: ["default"],
      persona: "regular",
      runtime_mode: "offline",
      workflow_audits: { enabled: false },
      suppress_findings: [],
    }),
    runScan: async () => makeReport([]),
    stdout: (message) => {
      output.push(message);
    },
    stderr: (message) => {
      output.push(message);
    },
    writeFile: () => {},
    setExitCode: () => {},
    ...overrides,
  };
}

async function runScanCommand(deps: CliDeps, args: string[]): Promise<void> {
  const cli = createCli("0.1.0", deps);
  await cli.parseAsync(["node", "codegate", "scan", ...args]);
}

describe("task 16 scan command", () => {
  it("sets exit code 0 when there are no unsuppressed findings", async () => {
    let exitCode = -1;
    const deps = buildDeps({
      runScan: async () => makeReport([]),
      setExitCode: (code) => {
        exitCode = code;
      },
    });

    await runScanCommand(deps, ["."]);
    expect(exitCode).toBe(0);
  });

  it("sets exit code 1 when findings exist below configured threshold", async () => {
    let exitCode = -1;
    const deps = buildDeps({
      runScan: async () => makeReport([makeFinding("MEDIUM")]),
      setExitCode: (code) => {
        exitCode = code;
      },
    });

    await runScanCommand(deps, ["."]);
    expect(exitCode).toBe(1);
  });

  it("sets exit code 2 when at least one finding meets threshold", async () => {
    let exitCode = -1;
    const deps = buildDeps({
      runScan: async () => makeReport([makeFinding("HIGH")]),
      setExitCode: (code) => {
        exitCode = code;
      },
    });

    await runScanCommand(deps, ["."]);
    expect(exitCode).toBe(2);
  });

  it("sets exit code 3 when scan execution throws", async () => {
    let exitCode = -1;
    const deps = buildDeps({
      runScan: async () => {
        throw new Error("boom");
      },
      setExitCode: (code) => {
        exitCode = code;
      },
    });

    await runScanCommand(deps, ["."]);
    expect(exitCode).toBe(3);
  });

  it("falls back to plain output in non-tty mode", async () => {
    const renderedViews: string[] = [];
    const printed: string[] = [];

    const deps = buildDeps({
      isTTY: () => false,
      runScan: async () => makeReport([]),
      stdout: (message) => {
        printed.push(message);
      },
      renderTui: ({ view }) => {
        renderedViews.push(view);
      },
    });

    await runScanCommand(deps, ["."]);
    expect(renderedViews).toHaveLength(0);
    expect(printed.length).toBeGreaterThan(0);
  });

  it("renders dashboard and summary views in tty mode", async () => {
    const renderedViews: string[] = [];

    const deps = buildDeps({
      isTTY: () => true,
      runScan: async () => makeReport([]),
      renderTui: ({ view }) => {
        renderedViews.push(view);
      },
    });

    await runScanCommand(deps, ["."]);
    expect(renderedViews).toEqual(["dashboard", "summary"]);
  });

  it("keeps TUI format in verbose mode", async () => {
    const renderedViews: string[] = [];
    const printed: string[] = [];

    const deps = buildDeps({
      isTTY: () => true,
      runScan: async () => makeReport([makeFinding("CRITICAL")]),
      renderTui: ({ view }) => {
        renderedViews.push(view);
      },
      stdout: (message) => {
        printed.push(message);
      },
    });

    await runScanCommand(deps, [".", "--verbose"]);
    expect(renderedViews).toEqual(["dashboard", "summary"]);
    expect(printed).toHaveLength(0);
  });

  it("enables user-scope scanning when flag is set", async () => {
    let receivedConfig: { scan_user_scope?: boolean } | undefined;

    const deps = buildDeps({
      runScan: async (input) => {
        receivedConfig = input.config;
        return makeReport([]);
      },
    });

    await runScanCommand(deps, [".", "--include-user-scope"]);
    expect(receivedConfig?.scan_user_scope).toBe(true);
  });

  it("uses default user-scope scanning when no override is provided", async () => {
    let receivedConfig: { scan_user_scope?: boolean } | undefined;

    const deps = buildDeps({
      resolveConfig: () => ({
        ...DEFAULT_CONFIG,
      }),
      runScan: async (input) => {
        receivedConfig = input.config;
        return makeReport([]);
      },
    });

    await runScanCommand(deps, ["."]);
    expect(receivedConfig?.scan_user_scope).toBe(true);
  });

  it("passes collection and strict flags into effective scan config", async () => {
    let receivedConfig:
      | {
          strict_collection?: boolean;
          scan_collection_modes?: string[];
        }
      | undefined;

    const deps = buildDeps({
      resolveConfig: () => ({
        ...DEFAULT_CONFIG,
      }),
      runScan: async (input) => {
        receivedConfig = input.config;
        return makeReport([]);
      },
    });

    await runScanCommand(deps, [
      ".",
      "--collect",
      "project",
      "--collect",
      "explicit",
      "--strict-collection",
    ]);

    expect(receivedConfig?.strict_collection).toBe(true);
    expect(receivedConfig?.scan_collection_modes).toEqual(["project", "explicit"]);
  });

  it("passes collection kind filters into effective scan config", async () => {
    let receivedConfig:
      | {
          scan_collection_kinds?: string[];
        }
      | undefined;

    const deps = buildDeps({
      resolveConfig: () => ({
        ...DEFAULT_CONFIG,
      }),
      runScan: async (input) => {
        receivedConfig = input.config;
        return makeReport([]);
      },
    });

    await runScanCommand(deps, [
      ".",
      "--collect-kind",
      "workflows",
      "--collect-kind",
      "dependabot",
    ]);

    expect(receivedConfig?.scan_collection_kinds).toEqual(["workflows", "dependabot"]);
  });
});
