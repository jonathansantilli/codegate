import { spawn } from "node:child_process";

export const DEFAULT_SANDBOX_TIMEOUT_MS = 30_000;

export interface SandboxCommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface SandboxCommandInput {
  command: string;
  args: string[];
  cwd: string;
  timeoutMs?: number;
}

export async function runSandboxCommand(input: SandboxCommandInput): Promise<SandboxCommandResult> {
  return await new Promise((resolve) => {
    const child = spawn(input.command, input.args, {
      cwd: input.cwd,
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, input.timeoutMs ?? DEFAULT_SANDBOX_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        code: timedOut ? 124 : (code ?? 1),
        stdout,
        stderr: timedOut ? `${stderr}\ncommand timed out` : stderr,
      });
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({
        code: 1,
        stdout,
        stderr: `${stderr}\n${error.message}`,
      });
    });
  });
}
