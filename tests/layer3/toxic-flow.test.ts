import { describe, expect, it } from "vitest";
import { detectToxicFlows } from "../../src/layer3-dynamic/toxic-flow";

describe("task 34 toxic flow analysis", () => {
  it("flags critical chain when input->sensitive->exfiltration tools coexist", () => {
    const findings = detectToxicFlows({
      scopeId: "workspace",
      tools: [
        { name: "jira_read_ticket", description: "Read Jira ticket content from remote projects" },
        { name: "filesystem_read", description: "Read local files including ~/.ssh/id_rsa" },
        { name: "slack_send_message", description: "Send data to Slack channel webhook" },
      ],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.category).toBe("TOXIC_FLOW");
    expect(findings[0]?.severity).toBe("CRITICAL");
    expect(findings[0]?.description).toContain("jira_read_ticket");
    expect(findings[0]?.description).toContain("filesystem_read");
    expect(findings[0]?.description).toContain("slack_send_message");
  });

  it("does not flag when one class of tool is missing", () => {
    const findings = detectToxicFlows({
      scopeId: "workspace",
      tools: [
        { name: "filesystem_read", description: "Read local files" },
        { name: "markdown_lint", description: "format markdown files" },
      ],
    });
    expect(findings).toHaveLength(0);
  });

  it("uses known classification labels when provided", () => {
    const findings = detectToxicFlows({
      scopeId: "workspace",
      tools: [{ name: "custom_tool", description: "unknown" }],
      knownClassifications: {
        custom_tool: ["untrusted_input", "sensitive_access", "exfiltration_sink"],
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.finding_id).toContain("TOXIC_FLOW");
  });
});
