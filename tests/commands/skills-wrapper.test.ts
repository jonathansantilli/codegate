import { describe, expect, it, vi } from "vitest";
import type { CodeGateConfig } from "../../src/config";
import {
  executeSkillsWrapper,
  parseSkillsInvocation,
  type SkillsWrapperDeps,
} from "../../src/commands/skills-wrapper";
import type { CodeGateReport } from "../../src/types/report";

const BASE_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: false,
  output_format: "terminal",
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
  suppression_rules: [],
  rule_pack_paths: [],
  allowed_rules: [],
  skip_rules: [],
};

function report(exitCode: 0 | 1 | 2): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-03-13T00:00:00.000Z",
    kb_version: "2026-03-13",
    tools_detected: ["codex-cli"],
    findings:
      exitCode === 0
        ? []
        : [
            {
              rule_id: "rule-file-remote-shell",
              finding_id: "RULE-1",
              severity: exitCode === 2 ? "CRITICAL" : "LOW",
              category: "RULE_INJECTION",
              layer: "L2",
              file_path: "skills/security-review/SKILL.md",
              location: { field: "remote_shell", line: 1, column: 1 },
              description: "Test finding",
              affected_tools: ["codex-cli"],
              cve: null,
              owasp: ["ASI01"],
              cwe: "CWE-116",
              confidence: "HIGH",
              fixable: true,
              remediation_actions: ["remove_block"],
              suppressed: false,
            },
          ],
    summary: {
      total: exitCode === 0 ? 0 : 1,
      by_severity: {
        CRITICAL: exitCode === 2 ? 1 : 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: exitCode === 1 ? 1 : 0,
        INFO: 0,
      },
      fixable: exitCode === 0 ? 0 : 1,
      suppressed: 0,
      exit_code: exitCode,
    },
  };
}

function makeDeps(overrides: Partial<SkillsWrapperDeps> = {}): SkillsWrapperDeps {
  return {
    cwd: () => "/tmp/project",
    isTTY: () => false,
    resolveConfig: (options) => ({
      ...BASE_CONFIG,
      output_format: options.cli?.format ?? BASE_CONFIG.output_format,
      tui: {
        ...BASE_CONFIG.tui,
        enabled: options.cli?.noTui ? false : BASE_CONFIG.tui.enabled,
      },
    }),
    runScan: async () => report(0),
    resolveScanTarget: async () => ({
      scanTarget: "/tmp/staged",
      displayTarget: "https://github.com/example/skills",
      cleanup: () => {},
    }),
    launchSkills: () => ({ status: 0 }),
    stdout: () => {},
    stderr: () => {},
    setExitCode: () => {},
    ...overrides,
  };
}

describe("skills wrapper parser", () => {
  it("parses wrapper flags and preserves passthrough args", () => {
    const parsed = parseSkillsInvocation([
      "add",
      "https://github.com/vercel-labs/skills",
      "--skill",
      "find-skills",
      "--cg-deep",
      "--cg-force",
      "--cg-no-tui",
      "--cg-format",
      "json",
      "--foo",
      "bar",
    ]);

    expect(parsed.wrapper.force).toBe(true);
    expect(parsed.wrapper.deep).toBe(true);
    expect(parsed.wrapper.noTui).toBe(true);
    expect(parsed.wrapper.format).toBe("json");
    expect(parsed.passthroughArgs).toEqual([
      "add",
      "https://github.com/vercel-labs/skills",
      "--skill",
      "find-skills",
      "--foo",
      "bar",
    ]);
  });

  it("detects add source target and preferred skill", () => {
    const parsed = parseSkillsInvocation([
      "add",
      "https://github.com/vercel-labs/skills",
      "--skill",
      "find-skills",
    ]);

    expect(parsed.subcommand).toBe("add");
    expect(parsed.sourceTarget).toBe("https://github.com/vercel-labs/skills");
    expect(parsed.preferredSkill).toBe("find-skills");
  });

  it("supports equals syntax for wrapper options", () => {
    const parsed = parseSkillsInvocation([
      "add",
      "owner/repo",
      "--cg-format=markdown",
      "--cg-config=/tmp/codegate.json",
    ]);

    expect(parsed.wrapper.format).toBe("markdown");
    expect(parsed.wrapper.configPath).toBe("/tmp/codegate.json");
    expect(parsed.passthroughArgs).toEqual(["add", "owner/repo"]);
  });

  it("throws for unknown wrapper options", () => {
    expect(() => parseSkillsInvocation(["add", "owner/repo", "--cg-unknown"])).toThrow(
      "Unknown CodeGate wrapper option",
    );
  });

  it("does not parse wrapper flags after -- delimiter", () => {
    const parsed = parseSkillsInvocation(["add", "owner/repo", "--", "--cg-force", "--cg-no-tui"]);

    expect(parsed.wrapper.force).toBe(false);
    expect(parsed.wrapper.noTui).toBe(false);
    expect(parsed.passthroughArgs).toEqual([
      "add",
      "owner/repo",
      "--",
      "--cg-force",
      "--cg-no-tui",
    ]);
  });

  it("throws for unsupported --cg-format values", () => {
    expect(() => parseSkillsInvocation(["add", "owner/repo", "--cg-format", "xml"])).toThrow(
      "Unsupported --cg-format value",
    );
  });

  it("throws when --cg-config is missing a value and next token is another option", () => {
    expect(() => parseSkillsInvocation(["add", "owner/repo", "--cg-config", "--cg-force"])).toThrow(
      "--cg-config requires a value",
    );
  });

  it("throws when --cg-format is missing a value and next token is another option", () => {
    expect(() =>
      parseSkillsInvocation(["add", "owner/repo", "--cg-format", "--cg-no-tui"]),
    ).toThrow("--cg-format requires a value");
  });

  it("supports --cg-deep wrapper option", () => {
    const parsed = parseSkillsInvocation(["add", "owner/repo", "--cg-deep"]);

    expect(parsed.wrapper.deep).toBe(true);
    expect(parsed.passthroughArgs).toEqual(["add", "owner/repo"]);
  });

  it("detects source when future option values appear before source target", () => {
    const parsed = parseSkillsInvocation([
      "add",
      "--some-future-flag",
      "value",
      "owner/repo",
      "--skill",
      "find-skills",
    ]);

    expect(parsed.sourceTarget).toBe("owner/repo");
  });

  it("prefers actual add source over option values that look like URLs", () => {
    const parsed = parseSkillsInvocation([
      "add",
      "--registry",
      "https://registry.example.internal",
      "owner/repo",
      "--skill",
      "find-skills",
    ]);

    expect(parsed.sourceTarget).toBe("owner/repo");
  });

  it("detects add even when global options with values appear before subcommand", () => {
    const parsed = parseSkillsInvocation([
      "--registry",
      "internal",
      "add",
      "owner/repo",
      "--skill",
      "find-skills",
    ]);

    expect(parsed.subcommand).toBe("add");
    expect(parsed.sourceTarget).toBe("owner/repo");
  });

  it("does not misclassify non-add commands that include `add` as an argument", () => {
    const parsed = parseSkillsInvocation(["find", "add", "security"]);

    expect(parsed.subcommand).toBe("find");
    expect(parsed.sourceTarget).toBe(null);
  });

  it("detects add and preferred skill when local source path relies on filesystem context", () => {
    const parsed = parseSkillsInvocation(
      ["--registry", "internal", "add", "skills", "--skill", "security-review"],
      {
        cwd: "/tmp/project",
        pathExists: () => true,
      },
    );

    expect(parsed.subcommand).toBe("add");
    expect(parsed.sourceTarget).toBe("skills");
    expect(parsed.preferredSkill).toBe("security-review");
  });
});

describe("skills wrapper execution", () => {
  it("passes through non-add commands directly", async () => {
    const launchSkills = vi.fn(() => ({ status: 0 }));
    const runScan = vi.fn(async () => report(0));
    let exitCode = -1;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: ["find", "security"],
      },
      makeDeps({
        launchSkills,
        runScan,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(runScan).not.toHaveBeenCalled();
    expect(launchSkills).toHaveBeenCalledWith(["find", "security"], "/tmp/project");
    expect(exitCode).toBe(0);
  });

  it("does not run preflight for non-add commands containing `add` in arguments", async () => {
    const launchSkills = vi.fn(() => ({ status: 0 }));
    const runScan = vi.fn(async () => report(0));
    let exitCode = -1;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: ["find", "add", "security"],
      },
      makeDeps({
        launchSkills,
        runScan,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(runScan).not.toHaveBeenCalled();
    expect(launchSkills).toHaveBeenCalledWith(["find", "add", "security"], "/tmp/project");
    expect(exitCode).toBe(0);
  });

  it("blocks add when preflight scan reports dangerous findings", async () => {
    const launchSkills = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: ["add", "https://github.com/vercel-labs/skills", "--skill", "find-skills"],
      },
      makeDeps({
        runScan: async () => report(2),
        launchSkills,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchSkills).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
  });

  it("blocks add when preflight scan fails and --cg-force is not set", async () => {
    const launchSkills = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: ["add", "https://github.com/vercel-labs/skills", "--skill", "find-skills"],
      },
      makeDeps({
        runScan: async () => {
          throw new Error("scan exploded");
        },
        launchSkills,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchSkills).not.toHaveBeenCalled();
    expect(exitCode).toBe(3);
  });

  it("continues add when preflight scan fails and --cg-force is set", async () => {
    const launchSkills = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-force",
        ],
      },
      makeDeps({
        runScan: async () => {
          throw new Error("scan exploded");
        },
        launchSkills,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchSkills).toHaveBeenCalledWith(
      ["add", "https://github.com/vercel-labs/skills", "--skill", "find-skills"],
      "/tmp/project",
    );
    expect(exitCode).toBe(0);
  });

  it("does not honor --cg-force when it appears after -- passthrough delimiter", async () => {
    const launchSkills = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--",
          "--cg-force",
        ],
      },
      makeDeps({
        runScan: async () => report(2),
        launchSkills,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchSkills).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
  });

  it("blocks warning findings in non-interactive mode when auto-proceed is disabled", async () => {
    const launchSkills = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: ["add", "https://github.com/vercel-labs/skills", "--skill", "find-skills"],
      },
      makeDeps({
        runScan: async () => report(1),
        launchSkills,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchSkills).not.toHaveBeenCalled();
    expect(exitCode).toBe(1);
  });

  it("continues warning findings in non-interactive mode when --cg-force is set", async () => {
    const launchSkills = vi.fn(() => ({ status: 0 }));
    let exitCode = -1;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-force",
        ],
      },
      makeDeps({
        runScan: async () => report(1),
        launchSkills,
        setExitCode: (code) => {
          exitCode = code;
        },
      }),
    );

    expect(launchSkills).toHaveBeenCalled();
    expect(exitCode).toBe(0);
  });

  it("normalizes owner/repo shorthand to GitHub URL for preflight scanning", async () => {
    const resolveScanTarget = vi.fn(async () => ({
      scanTarget: "/tmp/staged",
      displayTarget: "https://github.com/vercel-labs/skills",
      cleanup: () => {},
    }));

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: ["add", "vercel-labs/skills", "--skill", "find-skills", "--cg-force"],
      },
      makeDeps({
        resolveScanTarget,
        pathExists: () => false,
      }),
    );

    expect(resolveScanTarget).toHaveBeenCalledWith(
      expect.objectContaining({
        rawTarget: "https://github.com/vercel-labs/skills",
      }),
    );
  });

  it("keeps existing local owner/repo path without rewriting to GitHub URL", async () => {
    const resolveScanTarget = vi.fn(async () => ({
      scanTarget: "/tmp/staged",
      displayTarget: "vercel-labs/skills",
      cleanup: () => {},
    }));

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: ["add", "vercel-labs/skills", "--skill", "find-skills", "--cg-force"],
      },
      makeDeps({
        resolveScanTarget,
        pathExists: () => true,
      }),
    );

    expect(resolveScanTarget).toHaveBeenCalledWith(
      expect.objectContaining({
        rawTarget: "vercel-labs/skills",
      }),
    );
  });

  it("passes include-user-scope wrapper option into resolved config for scan", async () => {
    let resolvedConfig: CodeGateConfig | undefined;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-include-user-scope",
          "--cg-force",
        ],
      },
      makeDeps({
        runScan: async (input) => {
          resolvedConfig = input.config;
          return report(0);
        },
      }),
    );

    expect(resolvedConfig?.scan_user_scope).toBe(true);
  });

  it("passes granular policy controls into the scan config", async () => {
    let resolvedConfig: CodeGateConfig | undefined;

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: ["add", "https://github.com/vercel-labs/skills", "--skill", "find-skills"],
      },
      makeDeps({
        resolveConfig: (options) => ({
          ...BASE_CONFIG,
          output_format: options.cli?.format ?? BASE_CONFIG.output_format,
          tui: {
            ...BASE_CONFIG.tui,
            enabled: options.cli?.noTui ? false : BASE_CONFIG.tui.enabled,
          },
          rule_pack_paths: ["/tmp/rules/custom.json"],
          allowed_rules: ["rule-allow"],
          skip_rules: ["rule-skip"],
          suppress_findings: ["legacy-suppression"],
          suppression_rules: [
            {
              rule_id: "rule-allow",
              file_path: "skills/**/*.md",
              severity: "LOW",
              category: "RULE_INJECTION",
              cwe: "CWE-116",
              fingerprint: "sha256:policy-test",
            },
          ],
        }),
        runScan: async (input) => {
          resolvedConfig = input.config;
          return report(0);
        },
      }),
    );

    expect(resolvedConfig?.rule_pack_paths).toEqual(["/tmp/rules/custom.json"]);
    expect(resolvedConfig?.allowed_rules).toEqual(["rule-allow"]);
    expect(resolvedConfig?.skip_rules).toEqual(["rule-skip"]);
    expect(resolvedConfig?.suppress_findings).toEqual(["legacy-suppression"]);
    expect(resolvedConfig?.suppression_rules).toHaveLength(1);
  });

  it("runs deep discovery when --cg-deep is set", async () => {
    const discoverDeepResources = vi.fn(async () => []);

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-deep",
          "--cg-force",
        ],
      },
      makeDeps({
        discoverDeepResources,
      }),
    );

    expect(discoverDeepResources).toHaveBeenCalledTimes(1);
  });

  it("does not invoke deep consent callbacks in non-interactive mode", async () => {
    const discoverDeepResources = vi.fn(async () => [
      {
        id: "http:https://mcp.example/tools",
        request: {
          id: "http:https://mcp.example/tools",
          kind: "http",
          locator: "https://mcp.example/tools",
        },
        commandPreview: "GET https://mcp.example/tools",
      },
    ]);
    const requestDeepScanConsent = vi.fn(async () => true);
    const executeDeepResource = vi.fn();

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-deep",
        ],
      },
      makeDeps({
        isTTY: () => false,
        discoverDeepResources,
        requestDeepScanConsent,
        executeDeepResource,
      }),
    );

    expect(requestDeepScanConsent).not.toHaveBeenCalled();
    expect(executeDeepResource).not.toHaveBeenCalled();
  });

  it("runs preflight for add when global options with values appear before subcommand", async () => {
    const runScan = vi.fn(async () => report(0));
    const launchSkills = vi.fn(() => ({ status: 0 }));

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "--registry",
          "internal",
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-force",
        ],
      },
      makeDeps({
        runScan,
        launchSkills,
      }),
    );

    expect(runScan).toHaveBeenCalledTimes(1);
    expect(launchSkills).toHaveBeenCalledWith(
      [
        "--registry",
        "internal",
        "add",
        "https://github.com/vercel-labs/skills",
        "--skill",
        "find-skills",
      ],
      "/tmp/project",
    );
  });

  it("preserves preferred skill for add when global options precede a local source path", async () => {
    const resolveScanTarget = vi.fn(async () => ({
      scanTarget: "/tmp/staged",
      displayTarget: "skills/security-review",
      cleanup: () => {},
    }));

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "--registry",
          "internal",
          "add",
          "skills",
          "--skill",
          "security-review",
          "--cg-force",
        ],
      },
      makeDeps({
        resolveScanTarget,
        pathExists: () => true,
      }),
    );

    expect(resolveScanTarget).toHaveBeenCalledWith(
      expect.objectContaining({
        preferredSkill: "security-review",
      }),
    );
  });

  it("does not emit terminal-only target summary when output format is json", async () => {
    const stdout = vi.fn();

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "https://github.com/vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-force",
          "--cg-format",
          "json",
        ],
      },
      makeDeps({
        stdout,
      }),
    );

    expect(stdout).toHaveBeenCalledTimes(1);
    const rendered = String(stdout.mock.calls[0]?.[0] ?? "");
    expect(rendered.trim().startsWith("{")).toBe(true);
    expect(rendered).not.toContain("Requested URL target result:");
  });

  it("uses inferred source target even when unknown options with values come first", async () => {
    const resolveScanTarget = vi.fn(async () => ({
      scanTarget: "/tmp/staged",
      displayTarget: "https://github.com/vercel-labs/skills",
      cleanup: () => {},
    }));

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "--some-future-flag",
          "value",
          "vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-force",
        ],
      },
      makeDeps({
        resolveScanTarget,
        pathExists: () => false,
      }),
    );

    expect(resolveScanTarget).toHaveBeenCalledWith(
      expect.objectContaining({
        rawTarget: "https://github.com/vercel-labs/skills",
      }),
    );
  });

  it("uses actual add source when option value before it looks like a URL", async () => {
    const resolveScanTarget = vi.fn(async () => ({
      scanTarget: "/tmp/staged",
      displayTarget: "https://github.com/vercel-labs/skills",
      cleanup: () => {},
    }));

    await executeSkillsWrapper(
      {
        version: "0.1.0",
        skillsArgs: [
          "add",
          "--registry",
          "https://registry.example.internal",
          "vercel-labs/skills",
          "--skill",
          "find-skills",
          "--cg-force",
        ],
      },
      makeDeps({
        resolveScanTarget,
        pathExists: () => false,
      }),
    );

    expect(resolveScanTarget).toHaveBeenCalledWith(
      expect.objectContaining({
        rawTarget: "https://github.com/vercel-labs/skills",
      }),
    );
  });
});
