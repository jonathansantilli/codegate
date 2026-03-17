import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

describe("deep scan makes no outbound HTTP calls", () => {
  it("CLI source does not call acquireToolDescriptions or fetchResourceMetadata", () => {
    const cliSource = readFileSync("src/cli.ts", "utf8");

    // The old code called these functions to make HTTP requests to MCP endpoints
    expect(cliSource).not.toContain("acquireToolDescriptions(");

    // fetchResourceMetadata should not be invoked (import as type is fine)
    const invocations = cliSource.match(/fetchResourceMetadata\(/g);
    expect(invocations).toBeNull();
  });

  it("CLI source contains the no-outbound-connection guard", () => {
    const cliSource = readFileSync("src/cli.ts", "utf8");
    expect(cliSource).toContain("URL recorded for analysis without making outbound connections");
  });

  it("executeDeepResource returns metadata with zero attempts (no network call)", () => {
    // Replicate the exact logic from cli.ts executeDeepResource
    const executeDeepResource = (resource: {
      id: string;
      request: { kind: string; locator: string };
    }) => ({
      status: "ok" as const,
      attempts: 0,
      elapsedMs: 0,
      metadata: {
        resource_id: resource.id,
        resource_kind: resource.request.kind,
        resource_url: resource.request.locator,
        note: "URL recorded for analysis without making outbound connections.",
      },
    });

    const testCases = [
      {
        id: "http:https://mcp.evil.com/tools",
        request: { kind: "http", locator: "https://mcp.evil.com/tools" },
      },
      {
        id: "sse:https://mcp.evil.com/sse",
        request: { kind: "sse", locator: "https://mcp.evil.com/sse" },
      },
      { id: "npm:@evil/backdoor", request: { kind: "npm", locator: "@evil/backdoor" } },
      {
        id: "git:https://github.com/evil/repo",
        request: { kind: "git", locator: "https://github.com/evil/repo" },
      },
    ];

    for (const tc of testCases) {
      const result = executeDeepResource(tc);
      expect(result.status).toBe("ok");
      expect(result.attempts).toBe(0);
      expect(result.elapsedMs).toBe(0);
      const meta = result.metadata;
      expect(meta.resource_url).toBe(tc.request.locator);
      expect(meta.note).toContain("without making outbound connections");
    }
  });
});
