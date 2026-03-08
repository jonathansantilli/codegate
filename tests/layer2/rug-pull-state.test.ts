import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { CodeGateConfig } from "../../src/config";
import {
  evaluateScanStateSnapshots,
  extractMcpServerSnapshots,
  getScanStatePath,
  loadScanState,
  saveScanState,
  type McpServerSnapshot,
} from "../../src/layer2-static/state/scan-state";
import { runScanEngine } from "../../src/scan";

function snapshot(overrides: Partial<McpServerSnapshot>): McpServerSnapshot {
  return {
    serverId: "@anthropic/mcp-server-filesystem",
    serverName: "filesystem",
    configHash: "sha256:111",
    configPath: ".mcp.json",
    ...overrides,
  };
}

describe("task 30 rug-pull scan-state", () => {
  it("emits NEW_SERVER for first-seen server and persists state", () => {
    const dir = mkdtempSync(join(tmpdir(), "codegate-state-"));
    const statePath = join(dir, "scan-state.json");

    const result = evaluateScanStateSnapshots({
      snapshots: [snapshot({})],
      previousState: { servers: {} },
      nowIso: "2026-02-28T23:10:00.000Z",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.category).toBe("NEW_SERVER");
    expect(result.nextState.servers["@anthropic/mcp-server-filesystem"]?.first_seen).toBe(
      "2026-02-28T23:10:00.000Z",
    );

    saveScanState(result.nextState, statePath);
    expect(existsSync(statePath)).toBe(true);
    const loaded = loadScanState(statePath);
    expect(loaded.servers["@anthropic/mcp-server-filesystem"]?.config_hash).toBe("sha256:111");
  });

  it("emits CONFIG_CHANGE when known server hash changes", () => {
    const previousState = {
      servers: {
        "@anthropic/mcp-server-filesystem": {
          config_hash: "sha256:111",
          config_path: ".mcp.json",
          first_seen: "2026-02-01T00:00:00.000Z",
          last_seen: "2026-02-10T00:00:00.000Z",
        },
      },
    };

    const result = evaluateScanStateSnapshots({
      snapshots: [snapshot({ configHash: "sha256:999" })],
      previousState,
      nowIso: "2026-02-28T23:11:00.000Z",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.category).toBe("CONFIG_CHANGE");
    expect(result.findings[0]?.severity).toBe("HIGH");
    expect(result.findings[0]?.description).toContain("configuration has changed");
    expect(result.nextState.servers["@anthropic/mcp-server-filesystem"]?.config_hash).toBe(
      "sha256:999",
    );
    expect(result.nextState.servers["@anthropic/mcp-server-filesystem"]?.first_seen).toBe(
      "2026-02-01T00:00:00.000Z",
    );
  });

  it("does not emit finding when server hash is unchanged", () => {
    const previousState = {
      servers: {
        "@anthropic/mcp-server-filesystem": {
          config_hash: "sha256:111",
          config_path: ".mcp.json",
          first_seen: "2026-02-01T00:00:00.000Z",
          last_seen: "2026-02-10T00:00:00.000Z",
        },
      },
    };

    const result = evaluateScanStateSnapshots({
      snapshots: [snapshot({ configHash: "sha256:111" })],
      previousState,
      nowIso: "2026-02-28T23:12:00.000Z",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.nextState.servers["@anthropic/mcp-server-filesystem"]?.last_seen).toBe(
      "2026-02-28T23:12:00.000Z",
    );
  });

  it("writes deterministic JSON format for state file", () => {
    const dir = mkdtempSync(join(tmpdir(), "codegate-state-"));
    const statePath = join(dir, "scan-state.json");
    saveScanState(
      {
        servers: {
          "@anthropic/mcp-server-filesystem": {
            config_hash: "sha256:111",
            config_path: ".mcp.json",
            first_seen: "2026-02-01T00:00:00.000Z",
            last_seen: "2026-02-10T00:00:00.000Z",
          },
        },
      },
      statePath,
    );
    const raw = readFileSync(statePath, "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    expect(raw).toContain('"servers"');
  });

  it("expands leading tilde in custom scan-state paths", () => {
    expect(getScanStatePath("~/scan-state.json")).toBe(
      resolve(process.env.HOME ?? "", "scan-state.json"),
    );
  });

  it("returns empty state when state file is malformed", () => {
    const dir = mkdtempSync(join(tmpdir(), "codegate-state-malformed-"));
    const statePath = join(dir, "scan-state.json");
    writeFileSync(statePath, "{", "utf8");

    const loaded = loadScanState(statePath);
    expect(loaded).toEqual({ servers: {} });
  });

  it("integrates with scan engine and tracks config changes between scans", async () => {
    const dir = mkdtempSync(join(tmpdir(), "codegate-state-scan-"));
    const statePath = join(dir, "scan-state.json");
    const configPath = resolve(dir, ".mcp.json");
    const config: CodeGateConfig = {
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

    writeFileSync(
      configPath,
      JSON.stringify(
        {
          mcpServers: {
            filesystem: {
              command: ["npx", "-y", "@anthropic/mcp-server-filesystem"],
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const firstScan = await runScanEngine({
      version: "0.1.0",
      scanTarget: dir,
      config,
      scanStatePath: statePath,
    });
    expect(firstScan.findings.some((finding) => finding.category === "NEW_SERVER")).toBe(true);

    const secondScan = await runScanEngine({
      version: "0.1.0",
      scanTarget: dir,
      config,
      scanStatePath: statePath,
    });
    expect(secondScan.findings.some((finding) => finding.category === "NEW_SERVER")).toBe(false);
    expect(secondScan.findings.some((finding) => finding.category === "CONFIG_CHANGE")).toBe(false);

    writeFileSync(
      configPath,
      JSON.stringify(
        {
          mcpServers: {
            filesystem: {
              command: ["npx", "-y", "@anthropic/mcp-server-filesystem"],
              env: { SAFE: "changed" },
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const thirdScan = await runScanEngine({
      version: "0.1.0",
      scanTarget: dir,
      config,
      scanStatePath: statePath,
    });
    expect(thirdScan.findings.some((finding) => finding.category === "CONFIG_CHANGE")).toBe(true);
  });

  it("extracts snapshots from mcp_servers alias", () => {
    const snapshots = extractMcpServerSnapshots(".mcp.json", {
      mcp_servers: {
        alpha: {
          command: ["npx", "-y", "@example/alpha-server"],
        },
      },
    });

    expect(snapshots).toHaveLength(1);
    expect(snapshots[0]?.serverName).toBe("alpha");
    expect(snapshots[0]?.serverId).toBe("@example/alpha-server");
  });

  it("extracts snapshots from context_servers alias", () => {
    const snapshots = extractMcpServerSnapshots(".zed/settings.json", {
      context_servers: {
        remote: {
          url: "https://example.com/mcp",
        },
      },
    });

    expect(snapshots).toHaveLength(1);
    expect(snapshots[0]?.serverName).toBe("remote");
    expect(snapshots[0]?.serverId).toBe("url:https://example.com/mcp");
  });

  it("normalizes URL-based server IDs for host casing and query ordering", () => {
    const snapshots = extractMcpServerSnapshots(".mcp.json", {
      mcpServers: {
        remote: {
          url: "HTTPS://EXAMPLE.COM/mcp/?b=2&a=1",
        },
      },
    });

    expect(snapshots).toHaveLength(1);
    expect(snapshots[0]?.serverId).toBe("url:https://example.com/mcp?a=1&b=2");
  });

  it("extracts snapshots from Cline remoteMCPServers arrays", () => {
    const snapshots = extractMcpServerSnapshots("~/.cline/data/cache/remote_config_acme.json", {
      remoteMCPServers: [
        {
          name: "internal-code-search",
          url: "https://mcp.internal.example/code-search",
          alwaysEnabled: true,
        },
      ],
    });

    expect(snapshots).toHaveLength(1);
    expect(snapshots[0]?.serverName).toBe("internal-code-search");
    expect(snapshots[0]?.serverId).toBe("url:https://mcp.internal.example/code-search");
    expect(snapshots[0]?.serverPath).toBe("remoteMCPServers.0");
  });
});
