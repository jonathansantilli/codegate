export type MetaAgentTool = "claude" | "codex" | "generic";

export interface MetaAgentCommandInput {
  tool: MetaAgentTool;
  prompt: string;
  workingDirectory: string;
  binaryPath?: string;
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

export function buildMetaAgentCommand(input: MetaAgentCommandInput): MetaAgentCommand {
  const prompt = normalizePrompt(input.prompt);

  if (input.tool === "claude") {
    const command = input.binaryPath ?? "claude";
    const args = ["--print", "--max-turns", "1", "--output-format", "json", "--tools=", prompt];
    return {
      command,
      args,
      cwd: input.workingDirectory,
      preview: `${command} ${args.map(shellEscape).join(" ")}`,
    };
  }

  if (input.tool === "codex") {
    const command = input.binaryPath ?? "codex";
    const args = ["--quiet", "--approval-mode", "never", prompt];
    return {
      command,
      args,
      cwd: input.workingDirectory,
      preview: `${command} ${args.map(shellEscape).join(" ")}`,
    };
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
