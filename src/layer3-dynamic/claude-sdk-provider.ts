import { query } from "@anthropic-ai/claude-agent-sdk";

import type { SandboxCommandResult } from "./sandbox.js";
import { DEFAULT_SANDBOX_TIMEOUT_MS } from "./sandbox.js";

/**
 * Run Claude's layer-3 analysis via @anthropic-ai/claude-agent-sdk instead
 * of spawning the `claude` binary directly.
 *
 * Auth follows the SDK's default precedence: if ANTHROPIC_API_KEY is set it
 * wins, otherwise the SDK delegates to the bundled Claude binary which
 * reads the session written by `claude login` (~/.claude/settings.json).
 * No explicit key plumbing here — intentional, the whole point of the
 * swap is to reuse whatever auth the user already has.
 *
 * Contract matches runSandboxCommand so the caller in cli.ts can treat
 * this as a drop-in for the claude CLI path.
 */
export interface ClaudeSdkInput {
  prompt: string;
  cwd: string;
  readOnly: boolean;
  timeoutMs?: number;
}

const READ_ONLY_TOOLS = ["Read", "Glob", "Grep"] as const;

export async function runClaudeViaSdk(input: ClaudeSdkInput): Promise<SandboxCommandResult> {
  const timeoutMs = input.timeoutMs ?? DEFAULT_SANDBOX_TIMEOUT_MS;
  const abort = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    abort.abort();
  }, timeoutMs);

  // Mirror the CLI flag set from command-builder.ts. Non-readOnly = no
  // tools, one turn, plain completion. Read-only = file-read tools only,
  // auto-allowed so we don't deadlock on a permission prompt (no human in
  // the loop), permissionMode 'plan' blocks any write even if a tool slips
  // in via future SDK defaults.
  const options = input.readOnly
    ? {
        cwd: input.cwd,
        maxTurns: 10,
        permissionMode: "plan" as const,
        tools: [...READ_ONLY_TOOLS],
        allowedTools: [...READ_ONLY_TOOLS],
        abortController: abort,
      }
    : {
        cwd: input.cwd,
        maxTurns: 1,
        tools: [] as string[],
        abortController: abort,
      };

  try {
    const stream = query({ prompt: input.prompt, options });
    let finalResult: string | null = null;
    let errorMessage: string | null = null;

    for await (const message of stream) {
      if (message.type !== "result") {
        continue;
      }
      if (message.subtype === "success") {
        finalResult = message.result;
      } else {
        // SDK surfaces a structured error subtype — capture the whole
        // thing as stderr so the caller's existing diagnostic path
        // (parseMetaAgentOutput returning null → evidence snippet) sees
        // something useful.
        errorMessage = JSON.stringify(message);
      }
    }

    clearTimeout(timer);
    if (timedOut) {
      return { code: 124, stdout: "", stderr: "claude-agent-sdk: query timed out" };
    }
    if (finalResult !== null) {
      return { code: 0, stdout: finalResult, stderr: "" };
    }
    return { code: 1, stdout: "", stderr: errorMessage ?? "claude-agent-sdk: no result message" };
  } catch (error) {
    clearTimeout(timer);
    if (timedOut) {
      return { code: 124, stdout: "", stderr: "claude-agent-sdk: query timed out" };
    }
    return {
      code: 1,
      stdout: "",
      stderr: `claude-agent-sdk: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}
