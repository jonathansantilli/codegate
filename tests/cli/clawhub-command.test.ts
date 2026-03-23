import { describe, expect, it, vi } from "vitest";
import { createCli, type CliDeps } from "../../src/cli";
import { DEFAULT_CONFIG } from "../../src/config";
import type { CodeGateReport } from "../../src/types/report";

function makeDeps(overrides: Partial<CliDeps> = {}): CliDeps {
  const report: CodeGateReport = {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-03-14T00:00:00.000Z",
    kb_version: "2026-03-14",
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

  return {
    cwd: () => "/tmp/project",
    isTTY: () => false,
    resolveConfig: () => ({
      ...DEFAULT_CONFIG,
      scan_user_scope: false,
      tui: { enabled: false, colour_scheme: "default", compact_mode: false },
    }),
    runScan: async () => report,
    stdout: () => {},
    stderr: () => {},
    writeFile: () => {},
    setExitCode: () => {},
    ...overrides,
  };
}

function captureClawhubHelpOutput(): string {
  const output: string[] = [];
  const cli = createCli("0.1.0", makeDeps());
  const clawhubCommand = cli.commands.find((command) => command.name() === "clawhub");
  if (!clawhubCommand) {
    throw new Error("clawhub command not found");
  }

  clawhubCommand.configureOutput({
    writeOut: (message) => {
      output.push(message);
    },
    writeErr: (message) => {
      output.push(message);
    },
  });
  clawhubCommand.outputHelp();
  return output.join("");
}

describe("clawhub wrapper command", () => {
  it("forwards raw args to runClawhubWrapper without hardcoding clawhub options", async () => {
    const runClawhubWrapper = vi.fn(async () => {});
    const deps = makeDeps({
      runClawhubWrapper,
    });
    const cli = createCli("0.1.0", deps);

    await cli.parseAsync([
      "node",
      "codegate",
      "clawhub",
      "--registry",
      "https://registry.clawhub.ai",
      "install",
      "security-auditor",
      "--some-future-flag",
      "value",
    ]);

    expect(runClawhubWrapper).toHaveBeenCalledWith(
      expect.objectContaining({
        version: "0.1.0",
        clawhubArgs: [
          "--registry",
          "https://registry.clawhub.ai",
          "install",
          "security-auditor",
          "--some-future-flag",
          "value",
        ],
      }),
    );
  });

  it("documents CodeGate wrapper options in clawhub help output", () => {
    const help = captureClawhubHelpOutput();

    expect(help).toContain("--cg-force");
    expect(help).toContain("--cg-deep");
    expect(help).toContain("--cg-no-tui");
    expect(help).toContain("--cg-include-user-scope");
    expect(help).toContain("--cg-collect <mode>");
    expect(help).toContain("--cg-collect-kind <kind>");
    expect(help).toContain("--cg-persona <type>");
    expect(help).toContain("--cg-runtime-mode <mode>");
    expect(help).toContain("--cg-workflow-audits");
    expect(help).toContain("--cg-format <type>");
    expect(help).toContain("--cg-config <path>");
  });
});
