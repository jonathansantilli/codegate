import { describe, expect, it, vi } from "vitest";
import { createCli, type CliDeps } from "../../src/cli";
import type { CodeGateConfig } from "../../src/config";
import type { Finding } from "../../src/types/finding";
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

function finding(): Finding {
  return {
    rule_id: "env-base-url-override",
    finding_id: "ENV_OVERRIDE-.mcp.json-env.OPENAI_BASE_URL",
    severity: "CRITICAL",
    category: "ENV_OVERRIDE",
    layer: "L2",
    file_path: ".mcp.json",
    location: { field: "env.OPENAI_BASE_URL" },
    description: "redirected endpoint",
    affected_tools: ["codex-cli"],
    cve: null,
    owasp: ["ASI03"],
    cwe: "CWE-522",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field"],
    suppressed: false,
  };
}

function makeReport(findings: Finding[]): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-02-28T00:00:00.000Z",
    kb_version: "2026-02-28",
    tools_detected: ["codex-cli"],
    findings,
    summary: {
      total: findings.length,
      by_severity: {
        CRITICAL: findings.filter((item) => item.severity === "CRITICAL").length,
        HIGH: findings.filter((item) => item.severity === "HIGH").length,
        MEDIUM: findings.filter((item) => item.severity === "MEDIUM").length,
        LOW: findings.filter((item) => item.severity === "LOW").length,
        INFO: findings.filter((item) => item.severity === "INFO").length,
      },
      fixable: findings.filter((item) => item.fixable).length,
      suppressed: findings.filter((item) => item.suppressed).length,
      exit_code: 2,
    },
  };
}

function depsWithRemediation(runRemediation: NonNullable<CliDeps["runRemediation"]>): CliDeps {
  return {
    cwd: () => process.cwd(),
    isTTY: () => false,
    resolveConfig: () => BASE_CONFIG,
    runScan: async () => makeReport([finding()]),
    stdout: () => {},
    stderr: () => {},
    writeFile: () => {},
    setExitCode: () => {},
    runRemediation,
  };
}

describe("task 23 remediation flags", () => {
  it("invokes remediation flow for --remediate", async () => {
    const runRemediation = vi.fn(async ({ report }) => ({ report }));
    const cli = createCli("0.1.0", depsWithRemediation(runRemediation));

    await cli.parseAsync(["node", "codegate", "scan", ".", "--remediate"]);
    expect(runRemediation).toHaveBeenCalledTimes(1);
    expect(runRemediation.mock.calls[0]?.[0].flags.remediate).toBe(true);
  });

  it("invokes remediation flow for --fix-safe", async () => {
    const runRemediation = vi.fn(async ({ report }) => ({ report }));
    const cli = createCli("0.1.0", depsWithRemediation(runRemediation));

    await cli.parseAsync(["node", "codegate", "scan", ".", "--fix-safe"]);
    expect(runRemediation).toHaveBeenCalledTimes(1);
    expect(runRemediation.mock.calls[0]?.[0].flags.fixSafe).toBe(true);
  });

  it("passes dry-run and patch combinations to remediation flow", async () => {
    const runRemediation = vi.fn(async ({ report }) => ({ report }));
    const cli = createCli("0.1.0", depsWithRemediation(runRemediation));

    await cli.parseAsync([
      "node",
      "codegate",
      "scan",
      ".",
      "--remediate",
      "--dry-run",
      "--patch",
      "--output",
      "fixes.patch",
    ]);

    expect(runRemediation).toHaveBeenCalledTimes(1);
    expect(runRemediation.mock.calls[0]?.[0].flags.remediate).toBe(true);
    expect(runRemediation.mock.calls[0]?.[0].flags.dryRun).toBe(true);
    expect(runRemediation.mock.calls[0]?.[0].flags.patch).toBe(true);
    expect(runRemediation.mock.calls[0]?.[0].flags.output).toBe("fixes.patch");
  });

  it("requires explicit consent before applying --remediate changes in tty mode", async () => {
    const runRemediation = vi.fn(async ({ report }) => ({
      report,
      plannedCount: 1,
      appliedCount: 1,
      backupSessionId: "2026-03-01T12-00-00-aaaaaa",
    }));
    const printed: string[] = [];
    let exitCode = -1;

    const cli = createCli("0.1.0", {
      ...depsWithRemediation(runRemediation),
      isTTY: () => true,
      stdout: (message) => {
        printed.push(message);
      },
      setExitCode: (code) => {
        exitCode = code;
      },
      requestRemediationConsent: () => false,
    });

    await cli.parseAsync(["node", "codegate", "scan", ".", "--remediate"]);
    expect(runRemediation).not.toHaveBeenCalled();
    expect(printed.some((line) => line.includes("Remediation skipped by user."))).toBe(true);
    expect(exitCode).toBe(2);
  });

  it("prints remediation summary with backup guidance after apply", async () => {
    const runRemediation = vi.fn(async () => ({
      report: makeReport([]),
      plannedCount: 2,
      appliedCount: 2,
      appliedActions: [
        {
          findingId: "ENV_OVERRIDE-.mcp.json-env.OPENAI_BASE_URL",
          filePath: ".mcp.json",
          action: "remove_field",
        },
      ],
      backupSessionId: "2026-03-01T12-00-00-aaaaaa",
    }));
    const printed: string[] = [];

    const cli = createCli("0.1.0", {
      ...depsWithRemediation(runRemediation),
      isTTY: () => true,
      stdout: (message) => {
        printed.push(message);
      },
      requestRemediationConsent: () => true,
    });

    await cli.parseAsync(["node", "codegate", "scan", ".", "--remediate"]);
    expect(runRemediation).toHaveBeenCalledTimes(1);
    expect(printed.some((line) => line.includes("Remediation summary"))).toBe(true);
    expect(printed.some((line) => line.includes("Planned changes: 2"))).toBe(true);
    expect(printed.some((line) => line.includes("Applied changes: 2"))).toBe(true);
    expect(
      printed.some((line) => line.includes(".codegate-backup/2026-03-01T12-00-00-aaaaaa")),
    ).toBe(true);
    expect(printed.some((line) => line.includes("codegate undo"))).toBe(true);
    expect(printed.some((line) => line.includes("remove_field"))).toBe(true);
    expect(
      printed.some((line) => line.includes("ENV_OVERRIDE-.mcp.json-env.OPENAI_BASE_URL")),
    ).toBe(true);
  });

  it("skips remediation execution when no fixable findings exist", async () => {
    const runRemediation = vi.fn(async ({ report }) => ({
      report,
      plannedCount: 0,
      appliedCount: 0,
    }));
    const printed: string[] = [];

    const cli = createCli("0.1.0", {
      ...depsWithRemediation(runRemediation),
      isTTY: () => true,
      runScan: async () => makeReport([]),
      stdout: (message) => {
        printed.push(message);
      },
    });

    await cli.parseAsync(["node", "codegate", "scan", ".", "--remediate"]);
    expect(runRemediation).not.toHaveBeenCalled();
    expect(
      printed.some((line) => line.includes("No fixable findings available for remediation.")),
    ).toBe(true);
  });
});
