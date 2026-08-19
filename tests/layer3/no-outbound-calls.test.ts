import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { createDeepResourceExecutor } from "../../src/layer3-dynamic/deep-resource-executor";
import type { DeepScanResource } from "../../src/pipeline";

function resource(kind: DeepScanResource["request"]["kind"], locator: string): DeepScanResource {
  return {
    id: `${kind}:${locator}`,
    request: { id: `${kind}:${locator}`, kind, locator },
    commandPreview: "",
  };
}

describe("deep scan outbound-call policy", () => {
  it("CLI source does not call acquireToolDescriptions or fetchResourceMetadata", () => {
    const cliSource = readFileSync("src/cli.ts", "utf8");

    // The old code called these functions to make HTTP requests to MCP endpoints
    expect(cliSource).not.toContain("acquireToolDescriptions(");

    // fetchResourceMetadata should not be invoked (import as type is fine)
    const invocations = cliSource.match(/fetchResourceMetadata\(/g);
    expect(invocations).toBeNull();
  });

  it("executor source keeps the no-outbound-connection guard for URL resources", () => {
    const executorSource = readFileSync("src/layer3-dynamic/deep-resource-executor.ts", "utf8");
    expect(executorSource).toContain(
      "URL recorded for analysis without making outbound connections",
    );
  });

  it("records every resource without network calls in offline mode (the default)", async () => {
    const fetchSpy = vi.fn();
    const execute = createDeepResourceExecutor({ fetchImpl: fetchSpy as unknown as typeof fetch });

    const testCases: DeepScanResource[] = [
      resource("http", "https://mcp.evil.com/tools"),
      resource("sse", "https://mcp.evil.com/sse"),
      resource("npm", "@evil/backdoor"),
      resource("pypi", "evil-package"),
      resource("git", "https://github.com/evil/repo"),
    ];

    for (const testCase of testCases) {
      const offline = await execute(testCase, { runtimeMode: "offline" });
      const noContext = await execute(testCase);
      for (const result of [offline, noContext]) {
        expect(result.status).toBe("ok");
        expect(result.attempts).toBe(0);
        expect(result.elapsedMs).toBe(0);
        const metadata = result.metadata as Record<string, unknown>;
        expect(metadata.resource_url).toBe(testCase.request.locator);
        expect(String(metadata.note)).toContain("without making outbound connections");
      }
    }

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("never fetches URL resources even in online mode", async () => {
    const fetchSpy = vi.fn();
    const execute = createDeepResourceExecutor({ fetchImpl: fetchSpy as unknown as typeof fetch });

    for (const testCase of [
      resource("http", "https://mcp.evil.com/tools"),
      resource("sse", "https://mcp.evil.com/sse"),
      resource("git", "https://github.com/evil/repo"),
    ]) {
      const result = await execute(testCase, { runtimeMode: "online" });
      expect(result.attempts).toBe(0);
    }

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("fetches only pinned registry hosts for packages in online mode", async () => {
    const fetchSpy = vi.fn(
      async () =>
        new Response(JSON.stringify({ "dist-tags": { latest: "1.0.0" }, versions: {}, time: {} }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const execute = createDeepResourceExecutor({ fetchImpl: fetchSpy as unknown as typeof fetch });

    const result = await execute(resource("npm", "@evil/backdoor"), { runtimeMode: "online" });

    expect(result.status).toBe("ok");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const requestedUrl = String(fetchSpy.mock.calls[0]?.[0]);
    expect(requestedUrl.startsWith("https://registry.npmjs.org/")).toBe(true);
    const requestInit = fetchSpy.mock.calls[0]?.[1] as RequestInit;
    expect(requestInit.redirect).toBe("error");
  });
});
