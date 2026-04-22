import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_FETCH_MAX_BYTES,
  DEFAULT_FETCH_TIMEOUT_MS,
  fetchResourceMetadata,
  resourceFetcherOptionsFromConfig,
  type ResourceFetcherDeps,
} from "../../src/layer3-dynamic/resource-fetcher";

function depsWithFetch(fetchImpl: ResourceFetcherDeps["fetch"]): ResourceFetcherDeps {
  return {
    fetch: fetchImpl,
    runCommand: async () => ({ code: 0, stdout: "ok", stderr: "" }),
    sleep: async () => {},
    now: () => Date.now(),
  };
}

describe("resource-fetcher size limits", () => {
  it("rejects responses whose declared Content-Length exceeds maxBytes", async () => {
    const fetch = vi.fn(async () => {
      // Body that would exceed the limit; the fetcher should bail out before reading.
      return new Response("x".repeat(10), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-length": "5000000",
        },
      });
    });

    const result = await fetchResourceMetadata(
      { id: "npm:big", kind: "npm", locator: "big-package" },
      depsWithFetch(fetch),
      { maxBytes: 1024, maxRetries: 0 },
    );

    expect(result.status).toBe("network_error");
    expect(result.error).toContain("response_too_large");
  });

  it("aborts mid-stream when bytes exceed maxBytes despite a missing Content-Length", async () => {
    // A stream that emits chunks larger than the configured limit.
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("aaaaaaaaaa")); // 10 bytes
        controller.enqueue(new TextEncoder().encode("bbbbbbbbbb")); // 20 bytes total
        controller.close();
      },
    });
    const fetch = vi.fn(async () => {
      return new Response(body, {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const result = await fetchResourceMetadata(
      { id: "http:stream", kind: "http", locator: "https://example.com/stream" },
      depsWithFetch(fetch),
      { maxBytes: 15, maxRetries: 0 },
    );

    expect(result.status).toBe("network_error");
    expect(result.error).toContain("response_too_large");
  });

  it("accepts responses within the size limit and returns parsed metadata", async () => {
    const payload = JSON.stringify({ name: "@org/pkg", version: "1.0.0" });
    const fetch = vi.fn(async () => {
      return new Response(payload, {
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-length": String(Buffer.byteLength(payload, "utf8")),
        },
      });
    });

    const result = await fetchResourceMetadata(
      { id: "npm:pkg", kind: "npm", locator: "@org/pkg" },
      depsWithFetch(fetch),
      { maxBytes: 4096 },
    );

    expect(result.status).toBe("ok");
    expect(result.metadata).toEqual({ name: "@org/pkg", version: "1.0.0" });
  });

  it("passes the configured timeout to AbortController", async () => {
    let receivedSignal: AbortSignal | null = null;
    const fetch = vi.fn(async (_input, init?: RequestInit) => {
      receivedSignal = init?.signal ?? null;
      return new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    await fetchResourceMetadata(
      { id: "npm:ok", kind: "npm", locator: "ok" },
      depsWithFetch(fetch),
      { timeoutMs: 123, maxRetries: 0 },
    );

    // We cannot observe the timeout directly, but we can verify the abort
    // signal plumbed through the fetch call.
    expect(receivedSignal).not.toBeNull();
  });
});

describe("resourceFetcherOptionsFromConfig", () => {
  it("maps CodeGate config fields to fetcher options", () => {
    const options = resourceFetcherOptionsFromConfig({
      layer3_remote_fetch_timeout_ms: 7500,
      layer3_remote_fetch_max_bytes: 2048,
    });
    expect(options).toEqual({ timeoutMs: 7500, maxBytes: 2048 });
  });
});

describe("fetcher defaults", () => {
  it("exposes sensible defaults", () => {
    expect(DEFAULT_FETCH_TIMEOUT_MS).toBe(5000);
    expect(DEFAULT_FETCH_MAX_BYTES).toBe(1_048_576);
  });
});
