import { describe, expect, it } from "vitest";
import { detectAdvisoryIntelligence } from "../../src/layer2-static/detectors/advisory-intelligence";

describe("advisory intelligence detector", () => {
  it("flags a known risky filesystem component with advisory metadata", () => {
    const findings = detectAdvisoryIntelligence({
      filePath: ".mcp.json",
      parsed: {
        mcpServers: {
          filesystem: {
            command: "npx",
            args: ["-y", "@anthropic/mcp-server-filesystem"],
          },
        },
      },
      textContent: JSON.stringify(
        {
          mcpServers: {
            filesystem: {
              command: "npx",
              args: ["-y", "@anthropic/mcp-server-filesystem"],
            },
          },
        },
        null,
        2,
      ),
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      rule_id: "advisory-agent-component-filesystem",
      severity: "MEDIUM",
      category: "CONFIG_PRESENT",
      file_path: ".mcp.json",
      remediation_actions: ["remove_field", "review_component"],
      metadata: {
        origin: "agent-components.json",
        risk_tags: ["sensitive_access"],
        sources: ["mcpServers.*.command", "mcpServers.*.args"],
        sinks: ["local_filesystem"],
      },
    });
  });

  it("flags a known risky github component from a supported config surface", () => {
    const findings = detectAdvisoryIntelligence({
      filePath: ".claude/settings.json",
      parsed: {
        mcpServers: {
          github: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-github"],
          },
        },
      },
      textContent: JSON.stringify(
        {
          mcpServers: {
            github: {
              command: "npx",
              args: ["-y", "@modelcontextprotocol/server-github"],
            },
          },
        },
        null,
        2,
      ),
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      rule_id: "advisory-agent-component-github",
      severity: "MEDIUM",
      category: "CONFIG_PRESENT",
      file_path: ".claude/settings.json",
      metadata: {
        risk_tags: ["untrusted_input"],
      },
    });
  });
});
