import { runSandboxCommand, type SandboxCommandResult } from "./sandbox.js";

export type ResourceKind = "npm" | "pypi" | "git" | "http" | "sse";

export interface ResourceRequest {
  id: string;
  kind: ResourceKind;
  locator: string;
}

export interface ResourceFetcherOptions {
  maxRetries?: number;
  timeoutMs?: number;
}

export interface ResourceFetcherDeps {
  fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  runCommand: (command: string, args: string[]) => Promise<SandboxCommandResult>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
}

export interface ResourceFetchResult {
  status: "ok" | "auth_failure" | "timeout" | "network_error" | "command_error";
  metadata?: unknown;
  error?: string;
  attempts: number;
  elapsedMs: number;
}

function defaultDeps(): ResourceFetcherDeps {
  return {
    fetch: (input, init) => fetch(input, init),
    runCommand: async (command, args) =>
      runSandboxCommand({
        command,
        args,
        cwd: process.cwd(),
        timeoutMs: 5000,
      }),
    sleep: async (ms) => {
      await new Promise((resolve) => setTimeout(resolve, ms));
    },
    now: () => Date.now(),
  };
}

function endpointFor(request: ResourceRequest): string {
  if (request.kind === "npm") {
    const pkg = request.locator.startsWith("@")
      ? request.locator.replace("/", "%2f")
      : request.locator;
    return `https://registry.npmjs.org/${pkg}`;
  }
  if (request.kind === "pypi") {
    return `https://pypi.org/pypi/${request.locator}/json`;
  }
  return request.locator;
}

async function parseResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return (await response.json()) as unknown;
  }
  return await response.text();
}

function timeoutError(error: unknown): boolean {
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  return message.includes("timeout") || message.includes("aborted");
}

export async function fetchResourceMetadata(
  request: ResourceRequest,
  customDeps: ResourceFetcherDeps = defaultDeps(),
  options: ResourceFetcherOptions = {},
): Promise<ResourceFetchResult> {
  const deps = customDeps;
  const startedAt = deps.now();
  const maxRetries = options.maxRetries ?? 1;

  if (request.kind === "git") {
    const result = await deps.runCommand("git", ["ls-remote", request.locator, "HEAD"]);
    const elapsedMs = deps.now() - startedAt;
    if (result.code !== 0) {
      return {
        status: "command_error",
        attempts: 1,
        elapsedMs,
        error: result.stderr || `git exited with ${result.code}`,
      };
    }
    return {
      status: "ok",
      attempts: 1,
      elapsedMs,
      metadata: {
        reference: "HEAD",
        output: result.stdout.trim(),
      },
    };
  }

  const endpoint = endpointFor(request);
  const timeoutMs = options.timeoutMs ?? 5000;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const response = await deps.fetch(endpoint, { signal: controller.signal });
      clearTimeout(timer);

      if (response.status === 401 || response.status === 403) {
        return {
          status: "auth_failure",
          attempts: attempt + 1,
          elapsedMs: deps.now() - startedAt,
          error: `authentication failed for ${request.id}`,
        };
      }

      if (!response.ok) {
        if (attempt < maxRetries) {
          await deps.sleep(100 * (attempt + 1));
          continue;
        }
        return {
          status: "network_error",
          attempts: attempt + 1,
          elapsedMs: deps.now() - startedAt,
          error: `HTTP ${response.status}`,
        };
      }

      return {
        status: "ok",
        attempts: attempt + 1,
        elapsedMs: deps.now() - startedAt,
        metadata: await parseResponse(response),
      };
    } catch (error) {
      if (attempt < maxRetries) {
        await deps.sleep(100 * (attempt + 1));
        continue;
      }

      return {
        status: timeoutError(error) ? "timeout" : "network_error",
        attempts: attempt + 1,
        elapsedMs: deps.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  return {
    status: "network_error",
    attempts: maxRetries + 1,
    elapsedMs: deps.now() - startedAt,
    error: "unreachable",
  };
}
