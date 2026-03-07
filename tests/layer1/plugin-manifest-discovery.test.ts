import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CodeGateConfig } from "../../src/config";
import { runScanEngine } from "../../src/scan";

const BASE_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: true,
  output_format: "terminal",
  scan_state_path: "/tmp/codegate-scan-state.json",
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

describe("plugin manifest discovery integration", () => {
  it("flags insecure plugin source URLs from discovered plugin manifests", async () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-plugin-manifest-"));
    mkdirSync(join(root, ".opencode"), { recursive: true });

    writeFileSync(
      join(root, ".opencode", "plugins.json"),
      JSON.stringify(
        {
          plugins: [
            {
              name: "evil-plugin",
              source: "http://evil.example/plugin.tgz",
            },
          ],
        },
        null,
        2,
      ),
      "utf8",
    );

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: root,
      config: BASE_CONFIG,
    });

    expect(
      report.findings.some(
        (finding) =>
          finding.rule_id === "plugin-manifest-insecure-source-url" &&
          finding.file_path === ".opencode/plugins.json",
      ),
    ).toBe(true);
  });

  it("flags insecure plugin source URLs from discovered Cline marketplace manifests", async () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-plugin-manifest-cline-"));
    mkdirSync(join(root, ".cline"), { recursive: true });

    writeFileSync(
      join(root, ".cline", "marketplace.json"),
      JSON.stringify(
        {
          extensions: [
            {
              id: "cline.evil-extension",
              source: "http://evil.example/extension.tgz",
            },
          ],
        },
        null,
        2,
      ),
      "utf8",
    );

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: root,
      config: BASE_CONFIG,
    });

    expect(
      report.findings.some(
        (finding) =>
          finding.rule_id === "plugin-manifest-insecure-source-url" &&
          finding.file_path === ".cline/marketplace.json",
      ),
    ).toBe(true);
  });

  it("flags insecure extension registry URLs from discovered Kiro product manifests", async () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-plugin-manifest-kiro-"));
    mkdirSync(join(root, ".kiro"), { recursive: true });

    writeFileSync(
      join(root, ".kiro", "product.json"),
      JSON.stringify(
        {
          extensionsGallery: {
            serviceUrl: "http://evil.example/vscode/gallery",
            itemUrl: "http://evil.example/vscode/item",
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: root,
      config: BASE_CONFIG,
    });

    expect(
      report.findings.some(
        (finding) =>
          finding.rule_id === "plugin-manifest-insecure-source-url" &&
          finding.file_path === ".kiro/product.json",
      ),
    ).toBe(true);
  });

  it("flags non-allowlisted extension registry domains from discovered Kiro product manifests", async () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-plugin-manifest-kiro-allowlist-"));
    mkdirSync(join(root, ".kiro"), { recursive: true });

    writeFileSync(
      join(root, ".kiro", "product.json"),
      JSON.stringify(
        {
          extensionsGallery: {
            serviceUrl: "https://evil.example/vscode/gallery",
            itemUrl: "https://evil.example/vscode/item",
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: root,
      config: BASE_CONFIG,
    });

    expect(
      report.findings.some(
        (finding) =>
          finding.rule_id === "plugin-manifest-nonallowlisted-extension-registry" &&
          finding.file_path === ".kiro/product.json",
      ),
    ).toBe(true);
  });
});
