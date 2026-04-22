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
  /**
   * Maximum number of bytes accepted in the response body. Enforced against
   * both the declared `Content-Length` header (if present) and the running
   * byte count during streaming read. Defaults to 1 MiB.
   */
  maxBytes?: number;
}

export const DEFAULT_FETCH_TIMEOUT_MS = 5000;
export const DEFAULT_FETCH_MAX_BYTES = 1_048_576;

/**
 * Extract Layer 3 remote-fetch limits from the resolved CodeGate config.
 * Kept here so callers don't have to remember the config field names.
 */
export function resourceFetcherOptionsFromConfig(config: {
  layer3_remote_fetch_timeout_ms: number;
  layer3_remote_fetch_max_bytes: number;
}): ResourceFetcherOptions {
  return {
    timeoutMs: config.layer3_remote_fetch_timeout_ms,
    maxBytes: config.layer3_remote_fetch_max_bytes,
  };
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
      ? request.locator.replace(/\//g, "%2f")
      : request.locator;
    return `https://registry.npmjs.org/${pkg}`;
  }
  if (request.kind === "pypi") {
    return `https://pypi.org/pypi/${request.locator}/json`;
  }
  return request.locator;
}

/**
 * Read a response body while enforcing `maxBytes`. Returns the collected
 * string, or throws a tagged error if the declared `Content-Length` or the
 * streamed size exceeds the cap.
 */
async function readBodyWithLimit(response: Response, maxBytes: number): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const parsed = Number(declared);
    if (Number.isFinite(parsed) && parsed > maxBytes) {
      // Drain & release the stream without reading bytes.
      try {
        await response.body?.cancel();
      } catch {
        // no-op: cancel failures are non-fatal.
      }
      throw new Error(
        `response_too_large: declared Content-Length ${parsed} exceeds limit ${maxBytes}`,
      );
    }
  }

  const body = response.body;
  if (!body) {
    // No stream (e.g., HEAD or empty body): fall back to text().
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      throw new Error(`response_too_large: body ${Buffer.byteLength(text, "utf8")} > ${maxBytes}`);
    }
    return text;
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // no-op
        }
        throw new Error(`response_too_large: streamed ${total} > ${maxBytes}`);
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // releaseLock throws if the reader was already cancelled; ignore.
    }
  }

  const buffer = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
  return buffer.toString("utf8");
}

async function parseResponse(response: Response, maxBytes: number): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  const text = await readBodyWithLimit(response, maxBytes);
  if (contentType.includes("application/json")) {
    return JSON.parse(text) as unknown;
  }
  return text;
}

function timeoutError(error: unknown): boolean {
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  return message.includes("timeout") || message.includes("aborted");
}

function isResponseTooLarge(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.startsWith("response_too_large");
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
  const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_FETCH_MAX_BYTES;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let response: Response;
      try {
        response = await deps.fetch(endpoint, { signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }

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

      const metadata = await parseResponse(response, maxBytes);
      return {
        status: "ok",
        attempts: attempt + 1,
        elapsedMs: deps.now() - startedAt,
        metadata,
      };
    } catch (error) {
      // Size-limit breaches are deterministic — do not retry, surface as network_error.
      if (isResponseTooLarge(error)) {
        return {
          status: "network_error",
          attempts: attempt + 1,
          elapsedMs: deps.now() - startedAt,
          error: error instanceof Error ? error.message : String(error),
        };
      }

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
