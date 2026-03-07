import { describe, expect, it, vi } from "vitest";
import { createCli, type CliDeps } from "../../src/cli";
import { DEFAULT_CONFIG } from "../../src/config";
import type { ScanDiscoveryContext } from "../../src/scan";
import type { Finding } from "../../src/types/finding";
import type { CodeGateReport } from "../../src/types/report";

function makeReport(findings: Finding[] = []): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-03-07T00:00:00.000Z",
    kb_version: "2026-03-07",
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

function makeDiscoveryContext(root: string): ScanDiscoveryContext {
  return {
    absoluteTarget: root,
    kb: { schemaVersion: "2026-03-07", entries: [] },
    walked: { files: [], symlinkEscapes: [], circularSymlinks: [] },
    selected: [],
    parsedCandidates: [],
  };
}

function buildDeps(overrides: Partial<CliDeps>): CliDeps {
  return {
    cwd: () => process.cwd(),
    isTTY: () => false,
    resolveConfig: () => ({
      ...DEFAULT_CONFIG,
      scan_user_scope: false,
      tui: { enabled: false, colour_scheme: "default", compact_mode: false },
    }),
    runScan: async () => makeReport(),
    stdout: () => {},
    stderr: () => {},
    writeFile: () => {},
    setExitCode: () => {},
    ...overrides,
  };
}

describe("scan target resolution", () => {
  it("resolves non-directory scan targets before config lookup and scan execution", async () => {
    const resolveConfig = vi.fn(() => ({
      ...DEFAULT_CONFIG,
      scan_user_scope: false,
      tui: { enabled: false, colour_scheme: "default", compact_mode: false },
    }));
    const runScan = vi.fn(async () => makeReport());
    const cleanup = vi.fn();
    const discoveryContext = makeDiscoveryContext("/tmp/staged-skill");
    const prepareScanDiscovery = vi.fn(async () => discoveryContext);

    const deps = buildDeps({
      resolveConfig,
      runScan,
      prepareScanDiscovery,
    }) as CliDeps & {
      resolveScanTarget?: (input: { rawTarget: string; cwd: string }) => Promise<{
        scanTarget: string;
        displayTarget: string;
        cleanup?: () => Promise<void> | void;
      }>;
    };

    deps.resolveScanTarget = vi.fn(async () => ({
      scanTarget: "/tmp/staged-skill",
      displayTarget: "https://example.com/security-review/SKILL.md",
      explicitCandidates: [
        {
          reportPath: "skills/security-review/SKILL.md",
          absolutePath: "/tmp/staged-skill/skills/security-review/SKILL.md",
          format: "markdown",
          tool: "codex-cli",
        },
      ],
      cleanup,
    }));

    const cli = createCli("0.1.0", deps);
    await cli.parseAsync(["node", "codegate", "scan", "https://example.com/security-review/SKILL.md"]);

    expect(deps.resolveScanTarget).toHaveBeenCalledWith({
      rawTarget: "https://example.com/security-review/SKILL.md",
      cwd: process.cwd(),
    });
    expect(resolveConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        scanTarget: "/tmp/staged-skill",
      }),
    );
    expect(prepareScanDiscovery).toHaveBeenCalledWith(
      "/tmp/staged-skill",
      expect.objectContaining({
        scan_user_scope: false,
      }),
      {
        explicitCandidates: [
          {
            reportPath: "skills/security-review/SKILL.md",
            absolutePath: "/tmp/staged-skill/skills/security-review/SKILL.md",
            format: "markdown",
            tool: "codex-cli",
          },
        ],
      },
    );
    expect(runScan).toHaveBeenCalledWith(
      expect.objectContaining({
        scanTarget: "/tmp/staged-skill",
        discoveryContext,
      }),
    );
    expect(cleanup).toHaveBeenCalledTimes(1);
  });

  it("passes resolved discovery context into deep-scan discovery", async () => {
    const discoverDeepResources = vi.fn(async () => []);
    const discoveryContext = makeDiscoveryContext("/tmp/staged-repo");
    const prepareScanDiscovery = vi.fn(async () => discoveryContext);

    const deps = buildDeps({
      discoverDeepResources,
      prepareScanDiscovery,
    }) as CliDeps & {
      resolveScanTarget?: (input: { rawTarget: string; cwd: string }) => Promise<{
        scanTarget: string;
        displayTarget: string;
      }>;
    };

    deps.resolveScanTarget = vi.fn(async () => ({
      scanTarget: "/tmp/staged-repo",
      displayTarget: "https://github.com/example/skills.git",
    }));

    const cli = createCli("0.1.0", deps);
    await cli.parseAsync(["node", "codegate", "scan", "https://github.com/example/skills.git", "--deep"]);

    expect(discoverDeepResources).toHaveBeenCalledWith(
      "/tmp/staged-repo",
      expect.any(Object),
      discoveryContext,
    );
  });
});
