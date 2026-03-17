import { describe, expect, it } from "vitest";
import { buildMetaAgentCommand } from "../../src/layer3-dynamic/command-builder";

describe("meta-agent command builder sandboxing", () => {
  describe("Claude Code", () => {
    it("uses no tools in default mode", () => {
      const cmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
      });
      expect(cmd.args).toContain("--tools=");
      expect(cmd.args).toContain("--max-turns");
      expect(cmd.args[cmd.args.indexOf("--max-turns") + 1]).toBe("1");
      expect(cmd.args).not.toContain("--allowedTools");
      expect(cmd.args).not.toContain("--disallowedTools");
    });

    it("restricts to read-only tools in readOnlyAgent mode", () => {
      const cmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
        readOnlyAgent: true,
      });
      expect(cmd.args).toContain("--tools");
      expect(cmd.args).toContain("Read,Glob,Grep");
      expect(cmd.args).not.toContain("--tools=");
      expect(cmd.args).not.toContain("--allowedTools");
      expect(cmd.args).not.toContain("--disallowedTools");
    });

    it("uses strict whitelist — no blacklist needed in readOnlyAgent mode", () => {
      const cmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
        readOnlyAgent: true,
      });
      // --tools is a strict whitelist: only listed tools are available
      // No need for --disallowedTools since unlisted tools simply don't exist
      expect(cmd.args).toContain("--tools");
      expect(cmd.args).not.toContain("--disallowedTools");
      expect(cmd.args).not.toContain("--allowedTools");
    });

    it("allows multiple turns in readOnlyAgent mode", () => {
      const cmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
        readOnlyAgent: true,
      });
      const maxTurns = cmd.args[cmd.args.indexOf("--max-turns") + 1];
      expect(Number(maxTurns)).toBeGreaterThan(1);
    });

    it("preserves --print and --output-format json in both modes", () => {
      const defaultCmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
      });
      const readOnlyCmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
        readOnlyAgent: true,
      });
      for (const cmd of [defaultCmd, readOnlyCmd]) {
        expect(cmd.args).toContain("--print");
        expect(cmd.args).toContain("--output-format");
        expect(cmd.args).toContain("json");
      }
    });

    it("uses custom binary path when provided", () => {
      const cmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
        binaryPath: "/usr/local/bin/claude",
        readOnlyAgent: true,
      });
      expect(cmd.command).toBe("/usr/local/bin/claude");
    });
  });

  describe("Codex CLI", () => {
    it("uses approval-mode never in default mode", () => {
      const cmd = buildMetaAgentCommand({
        tool: "codex",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
      });
      expect(cmd.args).toContain("--approval-mode");
      expect(cmd.args).toContain("never");
    });

    it("uses approval-mode workspace in readOnlyAgent mode", () => {
      const cmd = buildMetaAgentCommand({
        tool: "codex",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
        readOnlyAgent: true,
      });
      expect(cmd.args).toContain("--approval-mode");
      expect(cmd.args).toContain("workspace");
      expect(cmd.args).not.toContain("never");
    });
  });

  describe("Generic (OpenCode)", () => {
    it("uses shell wrapper regardless of readOnlyAgent", () => {
      const cmd = buildMetaAgentCommand({
        tool: "generic",
        prompt: "analyze",
        workingDirectory: "/tmp/scan",
        binaryPath: "opencode",
        readOnlyAgent: true,
      });
      expect(cmd.command).toBe("sh");
      expect(cmd.args[0]).toBe("-lc");
      expect(cmd.preview).toContain("opencode");
    });
  });

  describe("prompt sanitization", () => {
    it("strips invisible unicode characters from prompts", () => {
      const cmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze\u200B\u200Cthis\u2060file\uFEFF",
        workingDirectory: "/tmp/scan",
      });
      expect(cmd.preview).not.toContain("\u200B");
      expect(cmd.preview).not.toContain("\u200C");
      expect(cmd.preview).not.toContain("\u2060");
      expect(cmd.preview).not.toContain("\uFEFF");
      expect(cmd.preview).toContain("analyzethisfile");
    });

    it("sets working directory correctly", () => {
      const cmd = buildMetaAgentCommand({
        tool: "claude",
        prompt: "analyze",
        workingDirectory: "/tmp/my-scan-target",
        readOnlyAgent: true,
      });
      expect(cmd.cwd).toBe("/tmp/my-scan-target");
    });
  });
});
