import { describe, expect, it, vi } from "vitest";
import { fetchRegistryMetadata, REGISTRY_KIND } from "../../src/layer3-dynamic/registry-client";
import { deriveRegistryFindings } from "../../src/layer3-dynamic/registry-findings";

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

const NPM_DOC = {
  "dist-tags": { latest: "2.1.0" },
  time: { created: "2020-01-01T00:00:00Z", "2.1.0": "2026-08-01T00:00:00Z" },
  maintainers: [{ name: "a" }, { name: "b" }],
  versions: {
    "2.1.0": {
      scripts: { postinstall: "node evil.js", test: "vitest" },
      deprecated: "use something else",
      repository: { url: "git+https://github.com/x/y.git" },
    },
  },
};

describe("registry client hardening", () => {
  it("parses npm metadata into the typed subset", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(NPM_DOC));
    const metadata = await fetchRegistryMetadata(REGISTRY_KIND.Npm, "some-pkg", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(metadata.latestVersion).toBe("2.1.0");
    expect(metadata.firstPublishedAt).toBe("2020-01-01T00:00:00Z");
    expect(metadata.latestPublishedAt).toBe("2026-08-01T00:00:00Z");
    expect(metadata.maintainerCount).toBe(2);
    expect(metadata.deprecated).toBe("use something else");
    expect(metadata.installScripts).toEqual(["postinstall"]);
    expect(metadata.repositoryUrl).toContain("github.com/x/y");
  });

  it("requests only the pinned host with redirects disabled", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(NPM_DOC));
    await fetchRegistryMetadata(REGISTRY_KIND.Npm, "@scope/pkg", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const url = String(fetchImpl.mock.calls[0]?.[0]);
    expect(url).toBe("https://registry.npmjs.org/@scope%2fpkg");
    const init = fetchImpl.mock.calls[0]?.[1] as RequestInit;
    expect(init.redirect).toBe("error");
    expect(init.signal).toBeDefined();
  });

  it("rejects oversized responses via content-length", async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response("{}", {
          status: 200,
          headers: {
            "content-type": "application/json",
            "content-length": String(10 * 1024 * 1024),
          },
        }),
    );

    await expect(
      fetchRegistryMetadata(REGISTRY_KIND.Npm, "big-pkg", {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/exceeds/u);
  });

  it("rejects oversized streamed bodies", async () => {
    const chunk = new Uint8Array(256 * 1024).fill(0x7b);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let index = 0; index < 8; index += 1) {
          controller.enqueue(chunk);
        }
        controller.close();
      },
    });
    const fetchImpl = vi.fn(
      async () =>
        new Response(stream, { status: 200, headers: { "content-type": "application/json" } }),
    );

    await expect(
      fetchRegistryMetadata(REGISTRY_KIND.Npm, "big-pkg", {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/exceeds/u);
  });

  it("propagates HTTP errors", async () => {
    const fetchImpl = vi.fn(async () => new Response("nope", { status: 404 }));
    await expect(
      fetchRegistryMetadata(REGISTRY_KIND.Npm, "missing", {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/HTTP 404/u);
  });
});

describe("registry findings", () => {
  const NOW = Date.parse("2026-08-19T00:00:00Z");

  function metadataFor(overrides: Record<string, unknown>): unknown {
    return {
      resource_id: "npm:pkg",
      registry: {
        kind: "npm",
        name: "pkg",
        latestVersion: "1.0.0",
        firstPublishedAt: null,
        latestPublishedAt: null,
        maintainerCount: 1,
        deprecated: null,
        installScripts: [],
        repositoryUrl: null,
        ...overrides,
      },
    };
  }

  it("flags install scripts as HIGH", () => {
    const findings = deriveRegistryFindings(
      "npm:pkg",
      metadataFor({ installScripts: ["postinstall"] }),
      {
        now: () => NOW,
      },
    );
    const finding = findings.find((entry) => entry.rule_id === "package-install-scripts");
    expect(finding?.severity).toBe("HIGH");
  });

  it("flags deprecated and recently published packages as MEDIUM", () => {
    const findings = deriveRegistryFindings(
      "npm:pkg",
      metadataFor({ deprecated: "abandoned", latestPublishedAt: "2026-08-10T00:00:00Z" }),
      { now: () => NOW, recentPublishDays: 30 },
    );
    expect(findings.map((entry) => entry.rule_id).sort()).toEqual([
      "package-deprecated",
      "package-recently-published",
    ]);
  });

  it("stays quiet for boring, established packages", () => {
    const findings = deriveRegistryFindings(
      "npm:pkg",
      metadataFor({ latestPublishedAt: "2024-01-01T00:00:00Z" }),
      { now: () => NOW },
    );
    expect(findings).toHaveLength(0);
  });
});
