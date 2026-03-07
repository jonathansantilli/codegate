import { describe, expect, it } from "vitest";
import {
  loadKnowledgeBase,
  validateKnowledgeBaseEntry,
} from "../../src/layer1-discovery/knowledge-base";

describe("task 07 knowledge base loader", () => {
  it("loads known tool entries from disk", () => {
    const kb = loadKnowledgeBase();
    const toolNames = kb.entries.map((entry) => entry.tool);

    expect(toolNames).toContain("claude-code");
    expect(toolNames).toContain("codex-cli");
    expect(toolNames).toContain("opencode");
    expect(toolNames).toContain("gemini-cli");
    expect(toolNames).toContain("roo-code");
    expect(toolNames).toContain("cline");
    expect(toolNames).toContain("zed");
    expect(toolNames).toContain("jetbrains-junie");
    expect(kb.schemaVersion).toBeTruthy();
  });

  it("reports validation errors for malformed entries", () => {
    const result = validateKnowledgeBaseEntry({
      version_range: ">=1.0.0",
      config_paths: [],
    });

    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });
});
