import { performance } from "node:perf_hooks";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { runScanEngine } from "../../src/scan";
import type { CodeGateConfig } from "../../src/config";

const PERF_CONFIG: CodeGateConfig = {
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

describe("task 19 scan performance", () => {
  it("completes layer 1+2 fixture scan under 2 seconds", async () => {
    const target = resolve(process.cwd(), "test-fixtures");
    const startedAt = performance.now();

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: target,
      config: PERF_CONFIG,
    });

    const elapsedMs = performance.now() - startedAt;
    expect(report.summary.total).toBeGreaterThanOrEqual(0);
    expect(elapsedMs).toBeLessThan(2000);
  });
});
