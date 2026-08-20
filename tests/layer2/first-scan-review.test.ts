import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { CodeGateConfig } from "../../src/config";
import {
  evaluateScanStateSnapshots,
  loadScanState,
  saveScanState,
  type McpServerSnapshot,
} from "../../src/layer2-static/state/scan-state";
import { runScanEngine } from "../../src/scan";

function snapshot(overrides: Partial<McpServerSnapshot> = {}): McpServerSnapshot {
  return {
    serverId: "@example/demo-server",
    serverName: "demo",
    configHash: "sha256:111",
    configPath: ".mcp.json",
    ...overrides,
  };
}

function baseConfig(overrides: Partial<CodeGateConfig> = {}): CodeGateConfig {
  return {
    severity_threshold: "high",
    auto_proceed_below_threshold: true,
    output_format: "terminal",
    tui: { enabled: false, colour_scheme: "default", compact_mode: false },
    tool_discovery: { preferred_agent: "claude", agent_paths: {}, skip_tools: [] },
    trusted_directories: [],
    blocked_commands: [],
    known_safe_mcp_servers: [],
    known_safe_formatters: [],
    known_safe_lsp_servers: [],
    known_safe_hooks: [],
    unicode_analysis: true,
    check_ide_settings: true,
    owasp_mapping: true,
    trusted_api_domains: [],
    suppress_findings: [],
    ...overrides,
  };
}

const tempDirs: string[] = [];
function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function writeMcpConfig(dir: string): void {
  writeFileSync(
    resolve(dir, ".mcp.json"),
    JSON.stringify(
      { mcpServers: { demo: { command: ["npx", "-y", "@example/demo-server"] } } },
      null,
      2,
    ),
    "utf8",
  );
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("first-scan review severity", () => {
  it("emits MEDIUM first-seen findings for untrusted targets", () => {
    const result = evaluateScanStateSnapshots({
      snapshots: [snapshot()],
      previousState: { servers: {} },
      trustedTarget: false,
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.rule_id).toBe("mcp-server-first-seen");
    expect(result.findings[0]?.severity).toBe("MEDIUM");
    expect(result.findings[0]?.description).toContain("untrusted");
  });

  it("emits INFO first-seen findings for trusted targets", () => {
    const result = evaluateScanStateSnapshots({
      snapshots: [snapshot()],
      previousState: { servers: {} },
      trustedTarget: true,
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe("INFO");
    expect(result.findings[0]?.description).not.toContain("untrusted");
  });

  it("records state without findings when first_scan_review is disabled", () => {
    const result = evaluateScanStateSnapshots({
      snapshots: [snapshot()],
      previousState: { servers: {} },
      firstScanReview: false,
    });

    expect(result.findings).toHaveLength(0);
    expect(result.nextState.servers["@example/demo-server"]).toBeDefined();
  });

  it("still emits CONFIG_CHANGE when first_scan_review is disabled", () => {
    const result = evaluateScanStateSnapshots({
      snapshots: [snapshot({ configHash: "sha256:999" })],
      previousState: {
        servers: {
          "@example/demo-server": {
            config_hash: "sha256:111",
            config_path: ".mcp.json",
            first_seen: "2026-01-01T00:00:00.000Z",
            last_seen: "2026-01-01T00:00:00.000Z",
          },
        },
      },
      firstScanReview: false,
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.category).toBe("CONFIG_CHANGE");
    expect(result.findings[0]?.severity).toBe("HIGH");
  });
});

describe("per-project scan state", () => {
  it("keeps baselines separate per project root", () => {
    const statePath = join(makeTempDir("codegate-state-projects-"), "scan-state.json");
    const projectA = "/workspace/project-a";
    const projectB = "/workspace/project-b";

    saveScanState(
      {
        servers: {
          "@example/demo-server": {
            config_hash: "sha256:111",
            config_path: ".mcp.json",
            first_seen: "2026-01-01T00:00:00.000Z",
            last_seen: "2026-01-01T00:00:00.000Z",
          },
        },
      },
      statePath,
      projectA,
    );

    expect(loadScanState(statePath, projectA).servers["@example/demo-server"]).toBeDefined();
    expect(loadScanState(statePath, projectB).servers).toEqual({});
  });

  it("preserves other projects when saving one project's state", () => {
    const statePath = join(makeTempDir("codegate-state-preserve-"), "scan-state.json");
    const entry = {
      config_hash: "sha256:111",
      config_path: ".mcp.json",
      first_seen: "2026-01-01T00:00:00.000Z",
      last_seen: "2026-01-01T00:00:00.000Z",
    };

    saveScanState({ servers: { "server-a": entry } }, statePath, "/workspace/project-a");
    saveScanState({ servers: { "server-b": entry } }, statePath, "/workspace/project-b");

    expect(loadScanState(statePath, "/workspace/project-a").servers["server-a"]).toBeDefined();
    expect(loadScanState(statePath, "/workspace/project-b").servers["server-b"]).toBeDefined();
  });

  it("discards legacy globally-keyed state files instead of leaking baselines", () => {
    const statePath = join(makeTempDir("codegate-state-legacy-"), "scan-state.json");
    writeFileSync(
      statePath,
      JSON.stringify({
        servers: {
          "@example/demo-server": {
            config_hash: "sha256:111",
            config_path: ".mcp.json",
            first_seen: "2026-01-01T00:00:00.000Z",
            last_seen: "2026-01-01T00:00:00.000Z",
          },
        },
      }),
      "utf8",
    );

    expect(loadScanState(statePath, "/workspace/project-a").servers).toEqual({});
    expect(loadScanState(statePath).servers).toEqual({});
  });

  it("re-reviews the same server in a second project and stays quiet on rescans", async () => {
    const statePath = join(makeTempDir("codegate-state-e2e-"), "scan-state.json");
    const projectA = makeTempDir("codegate-project-a-");
    const projectB = makeTempDir("codegate-project-b-");
    writeMcpConfig(projectA);
    writeMcpConfig(projectB);
    const config = baseConfig();

    const firstA = await runScanEngine({
      version: "0.1.0",
      scanTarget: projectA,
      config,
      scanStatePath: statePath,
    });
    const firstSeenA = firstA.findings.filter((finding) => finding.category === "NEW_SERVER");
    expect(firstSeenA).toHaveLength(1);
    expect(firstSeenA[0]?.severity).toBe("MEDIUM");

    // The same server in a different project must be reviewed again.
    const firstB = await runScanEngine({
      version: "0.1.0",
      scanTarget: projectB,
      config,
      scanStatePath: statePath,
    });
    expect(firstB.findings.filter((finding) => finding.category === "NEW_SERVER")).toHaveLength(1);

    const secondA = await runScanEngine({
      version: "0.1.0",
      scanTarget: projectA,
      config,
      scanStatePath: statePath,
    });
    expect(secondA.findings.filter((finding) => finding.category === "NEW_SERVER")).toHaveLength(0);
    expect(secondA.findings.filter((finding) => finding.category === "CONFIG_CHANGE")).toHaveLength(
      0,
    );
  });

  it("emits INFO first-seen findings when the target directory is trusted", async () => {
    const statePath = join(makeTempDir("codegate-state-trusted-"), "scan-state.json");
    const project = makeTempDir("codegate-project-trusted-");
    writeMcpConfig(project);

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: project,
      config: baseConfig({ trusted_directories: [project] }),
      scanStatePath: statePath,
    });

    const firstSeen = report.findings.filter((finding) => finding.category === "NEW_SERVER");
    expect(firstSeen).toHaveLength(1);
    expect(firstSeen[0]?.severity).toBe("INFO");
  });

  it("suppresses first-seen findings when first_scan_review is false", async () => {
    const statePath = join(makeTempDir("codegate-state-disabled-"), "scan-state.json");
    const project = makeTempDir("codegate-project-disabled-");
    writeMcpConfig(project);

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: project,
      config: baseConfig({ first_scan_review: false }),
      scanStatePath: statePath,
    });

    expect(report.findings.filter((finding) => finding.category === "NEW_SERVER")).toHaveLength(0);
  });
});
