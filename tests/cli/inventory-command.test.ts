import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createCli, type CliDeps } from "../../src/cli";
import type { CodeGateConfig } from "../../src/config";
import type { CodeGateReport } from "../../src/types/report";

const BASE_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: true,
  output_format: "terminal",
  scan_state_path: "/tmp/codegate-scan-state.json",
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

function makeDeps(overrides: Partial<CliDeps>): CliDeps & { stdoutChunks: string[] } {
  const stdoutChunks: string[] = [];
  const deps: CliDeps = {
    cwd: () => process.cwd(),
    isTTY: () => false,
    homeDir: () => "/tmp/codegate-home",
    pathExists: () => false,
    resolveConfig: () => BASE_CONFIG,
    runScan: async () => EMPTY_REPORT,
    stdout: (line) => stdoutChunks.push(line),
    stderr: () => {},
    writeFile: () => {},
    setExitCode: () => {},
    ...overrides,
  };
  return Object.assign(deps, { stdoutChunks });
}

describe("CLI inventory command", () => {
  let home: string;
  let workspace: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "codegate-inv-cli-home-"));
    workspace = mkdtempSync(join(tmpdir(), "codegate-inv-cli-ws-"));
  });

  afterEach(() => {
    for (const dir of [home, workspace]) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  });

  it("emits JSON when --format json is given", async () => {
    const deps = makeDeps({
      homeDir: () => home,
      cwd: () => workspace,
    });
    const cli = createCli("0.0.0-test", deps);
    let exitCode = -1;
    deps.setExitCode = (code) => {
      exitCode = code;
    };

    await cli.parseAsync(["node", "codegate", "inventory", "--format", "json"]);

    const combined = deps.stdoutChunks.join("\n");
    const parsed = JSON.parse(combined);

    expect(parsed.kb_version).toBeTruthy();
    expect(Array.isArray(parsed.tools)).toBe(true);
    expect(Array.isArray(parsed.items)).toBe(true);
    expect(exitCode).toBe(0);
  });

  it("filters to existing skill items when --only-existing and --kind skills", async () => {
    // Seed one Anthropic skill so the filter has something to return
    mkdirSync(join(home, ".claude", "skills", "alpha"), { recursive: true });
    writeFileSync(join(home, ".claude", "skills", "alpha", "SKILL.md"), "# alpha");

    const deps = makeDeps({
      homeDir: () => home,
      cwd: () => workspace,
    });
    const cli = createCli("0.0.0-test", deps);

    await cli.parseAsync([
      "node",
      "codegate",
      "inventory",
      "--format",
      "json",
      "--kind",
      "skills",
      "--only-existing",
    ]);

    const combined = deps.stdoutChunks.join("\n");
    const parsed = JSON.parse(combined) as {
      items: Array<{
        tool: string;
        type?: string;
        exists: boolean;
        path: string;
      }>;
    };

    expect(parsed.items.length).toBeGreaterThan(0);
    expect(parsed.items.every((i) => i.exists)).toBe(true);
    expect(
      parsed.items.some(
        (i) =>
          i.type === "anthropic_skill" &&
          i.path === join(home, ".claude", "skills", "alpha", "SKILL.md"),
      ),
    ).toBe(true);
  });

  it("renders human-readable text by default", async () => {
    const deps = makeDeps({
      homeDir: () => home,
      cwd: () => workspace,
    });
    const cli = createCli("0.0.0-test", deps);

    await cli.parseAsync(["node", "codegate", "inventory", "--scope", "user"]);

    const combined = deps.stdoutChunks.join("\n");
    expect(combined).toContain("Knowledge base v");
    expect(combined).toContain("Tools:");
    expect(combined).toContain("Items:");
  });
});
