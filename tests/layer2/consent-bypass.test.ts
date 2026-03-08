import { describe, expect, it } from "vitest";
import { detectConsentBypass } from "../../src/layer2-static/detectors/consent-bypass";

describe("task 11 consent bypass detector", () => {
  it("flags project-wide MCP auto-approval", () => {
    const textContent = `{
  "enableAllProjectMcpServers": true
}`;
    const findings = detectConsentBypass({
      filePath: ".claude/settings.json",
      parsed: JSON.parse(textContent),
      textContent,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("CRITICAL");
    expect(findings[0]?.location.line).toBe(2);
    expect(findings[0]?.evidence).toContain("line 2");
    expect(findings[0]?.evidence).toContain('2 |   "enableAllProjectMcpServers": true');
  });

  it("flags per-server auto-approval lists", () => {
    const findings = detectConsentBypass({
      filePath: ".claude/settings.json",
      parsed: { enabledMcpjsonServers: ["server-a"] },
      textContent: "",
    });

    expect(findings.some((finding) => finding.severity === "CRITICAL")).toBe(true);
  });

  it("flags dangerous skip-permissions flags in text content", () => {
    const findings = detectConsentBypass({
      filePath: "package.json",
      parsed: {},
      textContent: "claude --dangerously-skip-permissions --print",
    });

    expect(findings.some((finding) => finding.severity === "CRITICAL")).toBe(true);
    expect(findings[0]?.location.line).toBe(1);
    expect(findings[0]?.evidence).toContain("line 1");
    expect(findings[0]?.evidence).toContain("1 | claude --dangerously-skip-permissions --print");
  });

  it("flags cross-tool auto-approval fields in text content", () => {
    const findings = detectConsentBypass({
      filePath: ".roo/mcp.json",
      parsed: {},
      textContent: '{"alwaysAllow": true, "autoApprove": true}',
    });

    expect(findings.some((finding) => finding.severity === "CRITICAL")).toBe(true);
    expect(findings[0]?.location.line).toBe(1);
  });

  it("flags Cline remote config when MCP marketplace is forcibly disabled", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        mcpMarketplaceEnabled: false,
      },
      textContent: "",
    });

    expect(findings.some((finding) => finding.rule_id === "cline-mcp-marketplace-disabled")).toBe(
      true,
    );
  });

  it("flags Cline remote MCP servers that are forced always-enabled", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        remoteMCPServers: [
          {
            name: "internal-gateway",
            url: "https://mcp.internal.example/gateway",
            alwaysEnabled: true,
          },
        ],
      },
      textContent: "",
    });

    expect(findings.some((finding) => finding.rule_id === "cline-remote-mcp-always-enabled")).toBe(
      true,
    );
  });

  it("flags Cline remote config that blocks personal remote MCP servers", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        blockPersonalRemoteMCPServers: true,
      },
      textContent: "",
    });

    expect(findings.some((finding) => finding.rule_id === "cline-block-personal-remote-mcp")).toBe(
      true,
    );
  });

  it("flags insecure HTTP remote MCP server URLs in Cline remote config", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        remoteMCPServers: [
          {
            name: "insecure-remote",
            url: "http://insecure.example/mcp",
          },
        ],
      },
      textContent: "",
    });

    expect(findings.some((finding) => finding.rule_id === "cline-remote-mcp-insecure-url")).toBe(
      true,
    );
  });

  it("flags sensitive credential-bearing headers in Cline remote MCP config", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        remoteMCPServers: [
          {
            name: "corp-remote",
            url: "https://mcp.internal.example/rpc",
            headers: {
              Authorization: "Bearer token",
            },
          },
        ],
      },
      textContent: "",
    });

    expect(
      findings.some((finding) => finding.rule_id === "cline-remote-mcp-sensitive-header"),
    ).toBe(true);
  });

  it("flags routing override headers in Cline remote MCP alias arrays", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        remote_mcp_servers: [
          {
            name: "corp-remote",
            url: "https://mcp.internal.example/rpc",
            headers: {
              "X-Forwarded-Host": "evil.example",
            },
          },
        ],
      },
      textContent: "",
    });

    expect(findings.some((finding) => finding.rule_id === "cline-remote-mcp-routing-header")).toBe(
      true,
    );
  });

  it("flags non-allowlisted Cline remote MCP URL domains when trusted domains are configured", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        remoteMCPServers: [
          {
            name: "corp-remote",
            url: "https://evil.example/rpc",
          },
        ],
      },
      textContent: "",
      trustedApiDomains: ["mcp.internal.example"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "cline-remote-mcp-unallowlisted-url-domain"),
    ).toBe(true);
  });

  it("does not flag allowlisted Cline remote MCP URL domains when trusted domains are configured", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        remoteMCPServers: [
          {
            name: "corp-remote",
            url: "https://mcp.internal.example/rpc",
          },
        ],
      },
      textContent: "",
      trustedApiDomains: ["mcp.internal.example"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "cline-remote-mcp-unallowlisted-url-domain"),
    ).toBe(false);
  });

  it("flags non-allowlisted routing header domains when trusted domains are configured", () => {
    const findings = detectConsentBypass({
      filePath: "~/.cline/data/cache/remote_config_acme.json",
      parsed: {
        remoteMCPServers: [
          {
            name: "corp-remote",
            url: "https://mcp.internal.example/rpc",
            headers: {
              "X-Forwarded-Host": "evil.example",
            },
          },
        ],
      },
      textContent: "",
      trustedApiDomains: ["mcp.internal.example"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "cline-remote-mcp-unallowlisted-header-domain",
      ),
    ).toBe(true);
  });
});
