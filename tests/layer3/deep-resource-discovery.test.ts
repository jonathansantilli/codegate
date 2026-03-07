import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { discoverDeepScanResources } from "../../src/scan";

describe("deep resource discovery", () => {
  it("discovers remote MCP HTTP/SSE endpoints from project configs", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-deep-discovery-"));
    mkdirSync(join(root, ".claude"), { recursive: true });

    writeFileSync(
      join(root, ".mcp.json"),
      JSON.stringify(
        {
          mcpServers: {
            remoteA: {
              url: "https://example.com/mcp/tools",
            },
            localCommandServer: {
              command: ["npx", "-y", "@example/local-mcp"],
            },
            pythonServer: {
              command: ["uvx", "--from", "example-python-mcp"],
            },
            remoteB: {
              url: "https://example.com/sse",
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const resources = discoverDeepScanResources(root);
    expect(resources.map((resource) => resource.id)).toEqual([
      "http:https://example.com/mcp/tools",
      "npm:@example/local-mcp",
      "pypi:example-python-mcp",
      "sse:https://example.com/sse",
    ]);
    expect(
      resources.every(
        (resource) =>
          resource.request.kind === "http" ||
          resource.request.kind === "sse" ||
          resource.request.kind === "npm" ||
          resource.request.kind === "pypi",
      ),
    ).toBe(true);
  });

  it("discovers resources from mcp_servers and context_servers aliases", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-deep-discovery-alias-"));

    writeFileSync(
      join(root, ".mcp.json"),
      JSON.stringify(
        {
          mcp_servers: {
            npmAlias: {
              command: ["npx", "-y", "@example/alias-mcp"],
            },
          },
          nested: {
            context_servers: {
              remoteAlias: {
                url: "https://example.com/eventstream",
              },
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const resources = discoverDeepScanResources(root);
    expect(resources.map((resource) => resource.id)).toEqual([
      "npm:@example/alias-mcp",
      "sse:https://example.com/eventstream",
    ]);
  });

  it("discovers remote MCP server URLs from Cline remote config caches", () => {
    const root = mkdtempSync(join(tmpdir(), "codegate-deep-discovery-remote-config-root-"));
    const home = mkdtempSync(join(tmpdir(), "codegate-deep-discovery-remote-config-home-"));
    mkdirSync(join(home, ".cline", "data", "cache"), { recursive: true });

    writeFileSync(
      join(home, ".cline", "data", "cache", "remote_config_acme.json"),
      JSON.stringify(
        {
          remoteMCPServers: [
            {
              name: "internal-a",
              url: "https://internal.example.com/mcp",
            },
            {
              name: "internal-sse",
              url: "https://internal.example.com/eventstream",
            },
          ],
        },
        null,
        2,
      ),
      "utf8",
    );

    const resources = discoverDeepScanResources(root, undefined, {
      includeUserScope: true,
      homeDir: home,
    });

    expect(resources.map((resource) => resource.id)).toEqual([
      "http:https://internal.example.com/mcp",
      "sse:https://internal.example.com/eventstream",
    ]);
  });
});
