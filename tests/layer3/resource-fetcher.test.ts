import { describe, expect, it, vi } from "vitest";
import {
  fetchResourceMetadata,
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

describe("task 25 resource fetcher", () => {
  it("fetches npm metadata with retry-capable orchestration", async () => {
    const fetch = vi.fn(async () => {
      return new Response(JSON.stringify({ name: "@org/pkg", version: "1.0.0" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const result = await fetchResourceMetadata(
      { id: "npm:@org/pkg", kind: "npm", locator: "@org/pkg" },
      depsWithFetch(fetch),
    );

    expect(result.status).toBe("ok");
    expect(result.metadata).toEqual({ name: "@org/pkg", version: "1.0.0" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("encodes every slash in scoped npm locators before fetching registry metadata", async () => {
    const fetch = vi.fn(async () => {
      return new Response(JSON.stringify({ name: "@org/pkg", version: "1.0.0" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    await fetchResourceMetadata(
      { id: "npm:@org/pkg/nested", kind: "npm", locator: "@org/pkg/nested" },
      depsWithFetch(fetch),
    );

    expect(fetch).toHaveBeenCalledWith(
      "https://registry.npmjs.org/@org%2fpkg%2fnested",
      expect.any(Object),
    );
  });

  it("returns auth_failure for 401/403 responses without retry loop", async () => {
    const fetch = vi.fn(async () => {
      return new Response("unauthorized", { status: 401 });
    });

    const result = await fetchResourceMetadata(
      { id: "http:private", kind: "http", locator: "https://private.example/metadata" },
      depsWithFetch(fetch),
    );

    expect(result.status).toBe("auth_failure");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("returns timeout after exhausting retries", async () => {
    const fetch = vi.fn(async () => {
      throw new Error("timeout");
    });

    const result = await fetchResourceMetadata(
      {
        id: "pypi:pkg",
        kind: "pypi",
        locator: "requests",
      },
      depsWithFetch(fetch),
      { maxRetries: 2 },
    );

    expect(result.status).toBe("timeout");
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});
