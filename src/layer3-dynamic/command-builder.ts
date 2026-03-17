import { writeFileSync } from "node:fs";
import { join } from "node:path";

export type MetaAgentTool = "claude" | "codex" | "generic";

export interface MetaAgentCommandInput {
  tool: MetaAgentTool;
  prompt: string;
  workingDirectory: string;
  binaryPath?: string;
  readOnlyAgent?: boolean;
}

export interface MetaAgentCommand {
  command: string;
  args: string[];
  cwd: string;
  preview: string;
  timeoutMs?: number;
}

const INVISIBLE_UNICODE = /[\u200B-\u200D\u2060\uFEFF]/gu;

function shellEscape(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function normalizePrompt(prompt: string): string {
  return prompt.replace(INVISIBLE_UNICODE, "").replaceAll("\r", "").trim();
}

/**
 * Create a temporary opencode.json config that restricts to read-only tools.
 * Returns the path to the temp directory containing the config.
 */
function createOpenCodeReadOnlyConfig(workingDirectory: string): string {
  const config = {
    $schema: "https://opencode.ai/config.json",
    permission: {
      "*": "deny",
      read: "allow",
      grep: "allow",
      glob: "allow",
      list: "allow",
    },
  };
  writeFileSync(join(workingDirectory, "opencode.json"), JSON.stringify(config, null, 2));
  return workingDirectory;
}

export function buildMetaAgentCommand(input: MetaAgentCommandInput): MetaAgentCommand {
  const prompt = normalizePrompt(input.prompt);
  const readOnly = input.readOnlyAgent === true;

  if (input.tool === "claude") {
    const command = input.binaryPath ?? "claude";
    const args: string[] = readOnly
      ? [
          "--print",
          "--max-turns",
          "10",
          "--output-format",
          "json",
          "--permission-mode",
          "plan",
          "--tools",
          "Read,Glob,Grep",
          prompt,
        ]
      : ["--print", "--max-turns", "1", "--output-format", "json", "--tools=", prompt];
    return {
      command,
      args,
      cwd: input.workingDirectory,
      preview: `${command} ${args.map(shellEscape).join(" ")}`,
    };
  }

  if (input.tool === "codex") {
    const command = input.binaryPath ?? "codex";
    const args: string[] = readOnly
      ? ["--quiet", "--sandbox", "read-only", "-c", "network_access=false", prompt]
      : ["--quiet", "--approval-mode", "never", prompt];
    return {
      command,
      args,
      cwd: input.workingDirectory,
      preview: `${command} ${args.map(shellEscape).join(" ")}`,
    };
  }

  // Generic / OpenCode
  if (readOnly) {
    createOpenCodeReadOnlyConfig(input.workingDirectory);
  }
  const command = "sh";
  const genericToolBinary = input.binaryPath ?? "tool";
  const pipeCommand = `printf %s ${shellEscape(prompt)} | ${shellEscape(genericToolBinary)} --stdin --no-interactive`;
  return {
    command,
    args: ["-lc", pipeCommand],
    cwd: input.workingDirectory,
    preview: `${command} ${shellEscape("-lc")} ${shellEscape(pipeCommand)}`,
  };
}
