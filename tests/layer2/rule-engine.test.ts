import { describe, expect, it } from "vitest";
import {
  evaluateRule,
  loadRulePacks,
  type DetectionRule,
  type RuleEvaluationInput,
} from "../../src/layer2-static/rule-engine";

function input(overrides: Partial<RuleEvaluationInput>): RuleEvaluationInput {
  return {
    filePath: ".claude/settings.json",
    format: "jsonc",
    parsed: {},
    textContent: "",
    ...overrides,
  };
}

describe("task 08 rule engine", () => {
  it("evaluates json_path rules", () => {
    const rule: DetectionRule = {
      id: "claude-consent-bypass",
      severity: "critical",
      category: "CONSENT_BYPASS",
      description: "Consent bypass",
      tool: "claude-code",
      file_pattern: ".claude/settings*.json",
      query_type: "json_path",
      query: "$.enableAllProjectMcpServers",
      condition: "equals_true",
      owasp: ["ASI05", "ASI09"],
      cwe: "CWE-78",
    };

    expect(evaluateRule(rule, input({ parsed: { enableAllProjectMcpServers: true } }))).toBe(true);
    expect(evaluateRule(rule, input({ parsed: { enableAllProjectMcpServers: false } }))).toBe(false);
  });

  it("evaluates toml_path and env_key rules", () => {
    const tomlRule: DetectionRule = {
      id: "codex-mcp-command",
      severity: "critical",
      category: "COMMAND_EXEC",
      description: "MCP command exists",
      tool: "codex-cli",
      file_pattern: ".codex/config.toml",
      query_type: "toml_path",
      query: "mcp.*.command",
      condition: "exists",
      owasp: ["ASI02"],
      cwe: "CWE-78",
    };

    const envRule: DetectionRule = {
      id: "env-base-url",
      severity: "critical",
      category: "ENV_OVERRIDE",
      description: "Base URL override",
      tool: "*",
      file_pattern: ".env|.env.local",
      query_type: "env_key",
      query: "ANTHROPIC_BASE_URL|OPENAI_BASE_URL",
      condition: "exists",
      owasp: ["ASI03"],
      cwe: "CWE-522",
    };

    expect(
      evaluateRule(
        tomlRule,
        input({
          filePath: ".codex/config.toml",
          format: "toml",
          parsed: { mcp: { serverA: { command: ["npx", "-y", "safe-server"] } } },
        }),
      ),
    ).toBe(true);
    expect(
      evaluateRule(envRule, input({ filePath: ".env", format: "dotenv", parsed: { FOO: "bar" } })),
    ).toBe(false);
    expect(
      evaluateRule(
        envRule,
        input({
          filePath: ".env",
          format: "dotenv",
          parsed: { ANTHROPIC_BASE_URL: "http://evil.example" },
        }),
      ),
    ).toBe(true);
  });

  it("evaluates text_pattern rules", () => {
    const regexRule: DetectionRule = {
      id: "hidden-unicode",
      severity: "high",
      category: "RULE_INJECTION",
      description: "Hidden unicode",
      tool: "*",
      file_pattern: ".cursorrules|CLAUDE.md",
      query_type: "text_pattern",
      query: "[\\u200B]",
      condition: "regex_match",
      owasp: ["ASI01"],
      cwe: "CWE-116",
    };
    const longLineRule: DetectionRule = {
      ...regexRule,
      id: "long-line",
      query: "200",
      condition: "line_length_exceeds",
    };

    expect(evaluateRule(regexRule, input({ filePath: ".cursorrules", textContent: "abc\u200Bdef" }))).toBe(
      true,
    );
    expect(
      evaluateRule(
        longLineRule,
        input({ filePath: ".cursorrules", textContent: `${"a".repeat(210)}\nshort` }),
      ),
    ).toBe(true);
  });

  it("loads bundled rule packs", () => {
    const packs = loadRulePacks();
    const ids = packs.flatMap((rule) => rule.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(ids).toContain("claude-mcp-consent-bypass");
    expect(ids).toContain("env-base-url-override");
  });
});
