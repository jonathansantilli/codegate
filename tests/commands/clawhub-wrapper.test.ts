import { describe, expect, it, vi } from "vitest";
import type { CodeGateConfig } from "../../src/config";
import {
  executeClawhubWrapper,
  parseClawhubInvocation,
  type ClawhubWrapperDeps,
} from "../../src/commands/clawhub-wrapper";
import type { CodeGateReport } from "../../src/types/report";

const BASE_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: false,
  output_format: "terminal",
  scan_user_scope: false,
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

function report(exitCode: 0 | 1 | 2): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-03-14T00:00:00.000Z",
    kb_version: "2026-03-14",
    tools_detected: ["claude-code"],
    findings:
      exitCode === 0
        ? []
        : [
            {
              rule_id: "rule-file-remote-shell",
              finding_id: "RULE-1",
              severity: exitCode === 2 ? "CRITICAL" : "LOW",
              category: "RULE_INJECTION",
              layer: "L2",
              file_path: "skills/security-auditor/SKILL.md",
              location: { field: "remote_shell", line: 1, column: 1 },
              description: "Test finding",
              affected_tools: ["claude-code"],
              cve: null,
              owasp: ["ASI01"],
              cwe: "CWE-116",
              confidence: "HIGH",
              fixable: true,
              remediation_actions: ["remove_block"],
              suppressed: false,
            },
          ],
    summary: {
      total: exitCode === 0 ? 0 : 1,
      by_severity: {
        CRITICAL: exitCode === 2 ? 1 : 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: exitCode === 1 ? 1 : 0,
        INFO: 0,
      },
      fixable: exitCode === 0 ? 0 : 1,
      suppressed: 0,
      exit_code: exitCode,
    },
  };
}

function makeDeps(overrides: Partial<ClawhubWrapperDeps> = {}): ClawhubWrapperDeps {
  return {
    cwd: () => "/tmp/project",
    isTTY: () => false,
    resolveConfig: (options) => ({
      ...BASE_CONFIG,
      output_format: options.cli?.format ?? BASE_CONFIG.output_format,
      tui: {
        ...BASE_CONFIG.tui,
        enabled: options.cli?.noTui ? false : BASE_CONFIG.tui.enabled,
      },
    }),
    runScan: async () => report(0),
    stageClawhubTarget: async () => ({
      scanTarget: "/tmp/staged",
      displayTarget: "https://clawhub.ai/security-auditor",
      cleanup: () => {},
    }),
    launchClawhub: () => ({ status: 0 }),
    stdout: () => {},
    stderr: () => {},
    setExitCode: () => {},
    ...overrides,
  };
}

describe("clawhub wrapper parser", () => {
  it("parses wrapper flags and preserves passthrough args", () => {
    const parsed = parseClawhubInvocation([
      "install",
      "security-auditor",
      "--cg-force",
      "--cg-no-tui",
      "--cg-format",
      "json",
      "--workdir",
      "/tmp/ws",
    ]);

    expect(parsed.wrapper.force).toBe(true);
    expect(parsed.wrapper.noTui).toBe(true);
    expect(parsed.wrapper.format).toBe("json");
    expect(parsed.passthroughArgs).toEqual(["install", "security-auditor", "--workdir", "/tmp/ws"]);
  });

  it("detects install source target and requested version", () => {
    const parsed = parseClawhubInvocation(["install", "security-auditor", "--version", "1.0.0"]);

    expect(parsed.subcommand).toBe("install");
    expect(parsed.sourceTarget).toBe("security-auditor");
    expect(parsed.requestedVersion).toBe("1.0.0");
  });

  it("supports equals syntax for --version", () => {
    const parsed = parseClawhubInvocation(["install", "security-auditor", "--version=1.0.0"]);

    expect(parsed.requestedVersion).toBe("1.0.0");
  });

  it("does not parse wrapper flags after -- delimiter", () => {
    const parsed = parseClawhubInvocation(["install", "security-auditor", "--", "--cg-force"]);

    expect(parsed.wrapper.force).toBe(false);
    expect(parsed.passthroughArgs).toEqual(["install", "security-auditor", "--", "--cg-force"]);
  });

  it("throws for unknown wrapper options", () => {
    expect(() => parseClawhubInvocation(["install", "security-auditor", "--cg-unknown"])).toThrow(
      "Unknown CodeGate wrapper option",
    );
  });

  it("throws when --cg-config is missing a value and next token is another option", () => {
    expect(() =>
      parseClawhubInvocation(["install", "security-auditor", "--cg-config", "--cg-force"]),
    ).toThrow("--cg-config requires a value");
  });

  it("detects install even when global options with values appear before subcommand", () => {
    const parsed = parseClawhubInvocation([
      "--registry",
      "https://registry.clawhub.ai",
      "install",
      "security-auditor",
    ]);

    expect(parsed.subcommand).toBe("install");
    expect(parsed.sourceTarget).toBe("security-auditor");
  });

  it("skips unknown option values when a source token follows", () => {
    const parsed = parseClawhubInvocation([
      "install",
      "--future-option",
      "value",
      "security-auditor",
    ]);

    expect(parsed.subcommand).toBe("install");
    expect(parsed.sourceTarget).toBe("security-auditor");
  });

  it("does not misclassify non-install commands that include install as an argument", () => {
    const parsed = parseClawhubInvocation(["search", "install", "security"]);

    expect(parsed.subcommand).toBe("search");
    expect(parsed.sourceTarget).toBe(null);
  });
});

describe("clawhub wrapper execution", () => {
  it("passes through non-install commands directly", async () => {
    const launchClawhub = vi.fn(() => ({ status: 0 }));
    const runScan = vi.fn(async () => report(0));
    let exitCode = -1;

    await executeClawhubWrapper(
      {
        version: "0.1.0",
        clawhubArgs: ["search", "security"],
      },
      makeDeps({
        launchClawhub,
        runScan,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(runScan).not.toHaveBeenCalled();
    expect(launchClawhub).toHaveBeenCalledWith(["search", "security"], "/tmp/project");
    expect(exitCode).toBe(0);
  });

  it("blocks install when preflight scan reports dangerous findings", async () => {
    const launchClawhub = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeClawhubWrapper(
      {
        version: "0.1.0",
        clawhubArgs: ["install", "security-auditor"],
      },
      makeDeps({
        runScan: async () => report(2),
        launchClawhub,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchClawhub).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
  });

  it("blocks install when preflight scan fails and --cg-force is not set", async () => {
    const launchClawhub = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeClawhubWrapper(
      {
        version: "0.1.0",
        clawhubArgs: ["install", "security-auditor"],
      },
      makeDeps({
        runScan: async () => {
          throw new Error("scan exploded");
        },
        launchClawhub,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchClawhub).not.toHaveBeenCalled();
    expect(exitCode).toBe(3);
  });

  it("continues install when preflight scan fails and --cg-force is set", async () => {
    const launchClawhub = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeClawhubWrapper(
      {
        version: "0.1.0",
        clawhubArgs: ["install", "security-auditor", "--cg-force"],
      },
      makeDeps({
        runScan: async () => {
          throw new Error("scan exploded");
        },
        launchClawhub,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchClawhub).toHaveBeenCalledWith(["install", "security-auditor"], "/tmp/project");
    expect(exitCode).toBe(0);
  });

  it("does not honor --cg-force when it appears after -- passthrough delimiter", async () => {
    const launchClawhub = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeClawhubWrapper(
      {
        version: "0.1.0",
        clawhubArgs: ["install", "security-auditor", "--", "--cg-force"],
      },
      makeDeps({
        runScan: async () => report(2),
        launchClawhub,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchClawhub).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
  });

  it("stages install target with requested version for preflight scan", async () => {
    const stageClawhubTarget = vi.fn(async () => ({
      scanTarget: "/tmp/staged",
      displayTarget: "https://clawhub.ai/security-auditor",
      cleanup: () => {},
    }));

    await executeClawhubWrapper(
      {
        version: "0.1.0",
        clawhubArgs: ["install", "security-auditor", "--version", "1.0.0", "--cg-force"],
      },
      makeDeps({
        stageClawhubTarget,
      }),
    );

    expect(stageClawhubTarget).toHaveBeenCalledWith(
      expect.objectContaining({
        sourceTarget: "security-auditor",
        requestedVersion: "1.0.0",
      }),
    );
  });
});
