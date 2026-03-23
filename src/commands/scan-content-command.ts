import { applyConfigPolicy, type CodeGateConfig } from "../config.js";
import { loadKnowledgeBase } from "../layer1-discovery/knowledge-base.js";
import { parseConfigContent } from "../layer1-discovery/config-parser.js";
import { runStaticPipeline } from "../pipeline.js";
import { renderByFormat } from "./scan-command/helpers.js";

export const SCAN_CONTENT_TYPES = ["json", "yaml", "toml", "markdown", "text"] as const;
export type ScanContentType = (typeof SCAN_CONTENT_TYPES)[number];

export interface ExecuteScanContentCommandInput {
  version: string;
  cwd: string;
  content: string;
  type: ScanContentType;
  config: CodeGateConfig;
}

export interface ExecuteScanContentCommandDeps {
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  setExitCode: (code: number) => void;
}

function toReportPath(type: ScanContentType): string {
  if (type === "markdown") {
    return "scan-content.md";
  }
  if (type === "text") {
    return "scan-content.txt";
  }
  return `scan-content.${type}`;
}

export async function executeScanContentCommand(
  input: ExecuteScanContentCommandInput,
  deps: ExecuteScanContentCommandDeps,
): Promise<void> {
  try {
    const parsed = parseConfigContent(input.content, input.type);
    if (!parsed.ok) {
      throw new Error(parsed.error);
    }

    const kbVersion = loadKnowledgeBase().schemaVersion;
    const report = applyConfigPolicy(
      await runStaticPipeline({
        version: input.version,
        kbVersion,
        scanTarget: `scan-content:${input.type}`,
        toolsDetected: [],
        projectRoot: input.cwd,
        files: [
          {
            filePath: toReportPath(input.type),
            format: input.type,
            parsed: parsed.data,
            textContent: input.content,
          },
        ],
        symlinkEscapes: [],
        hooks: [],
        config: {
          knownSafeMcpServers: input.config.known_safe_mcp_servers,
          knownSafeFormatters: input.config.known_safe_formatters,
          knownSafeLspServers: input.config.known_safe_lsp_servers,
          knownSafeHooks: input.config.known_safe_hooks,
          blockedCommands: input.config.blocked_commands,
          trustedApiDomains: input.config.trusted_api_domains,
          unicodeAnalysis: input.config.unicode_analysis,
          checkIdeSettings: input.config.check_ide_settings,
          rulePackPaths: input.config.rule_pack_paths,
          allowedRules: input.config.allowed_rules,
          skipRules: input.config.skip_rules,
          persona: input.config.persona,
          runtimeMode: input.config.runtime_mode,
          workflowAuditsEnabled: input.config.workflow_audits?.enabled === true,
          rulePolicies: input.config.rules,
        },
      }),
      input.config,
    );

    deps.stdout(renderByFormat(input.config.output_format, report));
    deps.setExitCode(report.summary.exit_code);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    deps.stderr(`Scan content failed: ${message}`);
    deps.setExitCode(3);
  }
}
