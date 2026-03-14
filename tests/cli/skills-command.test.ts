import { describe, expect, it, vi } from "vitest";
import { createCli, type CliDeps } from "../../src/cli";
import { DEFAULT_CONFIG } from "../../src/config";
import type { CodeGateReport } from "../../src/types/report";

function makeDeps(overrides: Partial<CliDeps> = {}): CliDeps {
  const report: CodeGateReport = {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-03-13T00:00:00.000Z",
    kb_version: "2026-03-13",
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

describe("skills wrapper command", () => {
  it("forwards raw args to runSkillsWrapper without hardcoding skills options", async () => {
    const runSkillsWrapper = vi.fn(async () => {});
    const deps = makeDeps({
      runSkillsWrapper,
    });
    const cli = createCli("0.1.0", deps);

    await cli.parseAsync([
      "node",
      "codegate",
      "skills",
      "add",
      "https://github.com/vercel-labs/skills",
      "--skill",
      "find-skills",
      "--some-future-flag",
      "value",
    ]);

    expect(runSkillsWrapper).toHaveBeenCalledWith(
      expect.objectContaining({
        version: "0.1.0",
        skillsArgs: [
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--some-future-flag",
          "value",
        ],
      }),
    );
  });
});
