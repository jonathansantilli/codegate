import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseContentBundle, verifyBundleSignature } from "../../src/content/content-bundle";
import {
  getActiveContentVersion,
  listInstalledContentVersions,
  loadActiveContentBundle,
  resetContentStoreCache,
} from "../../src/content/content-store";
import {
  checkContentUpdate,
  rollbackContent,
  updateContent,
} from "../../src/content/content-updater";
import { loadKnownBadIndicators, resetKnownBadIndicatorsCache } from "../../src/content/known-bad";
import { loadKnowledgeBase } from "../../src/layer1-discovery/knowledge-base";

vi.mock("../../src/content/publisher-key", async () => {
  const { generateKeyPairSync: generate } = await import("node:crypto");
  const pair = generate("ed25519");
  return {
    CONTENT_PUBLISHER_PUBLIC_KEY_PEM: pair.publicKey.export({
      type: "spki",
      format: "pem",
    }) as string,
    __testPrivateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  };
});

async function testKeys(): Promise<{ publicPem: string; privatePem: string }> {
  const mocked = (await import("../../src/content/publisher-key")) as unknown as {
    CONTENT_PUBLISHER_PUBLIC_KEY_PEM: string;
    __testPrivateKeyPem: string;
  };
  return {
    publicPem: mocked.CONTENT_PUBLISHER_PUBLIC_KEY_PEM,
    privatePem: mocked.__testPrivateKeyPem,
  };
}

function signBundle(bundleBytes: Buffer, privatePem: string): string {
  return sign(null, bundleBytes, createPrivateKey(privatePem)).toString("base64");
}

function makeBundle(contentVersion: string, extra: Record<string, unknown> = {}): Buffer {
  return Buffer.from(
    JSON.stringify({
      schema_version: "1",
      content_version: contentVersion,
      released_at: `2026-08-${contentVersion.slice(-2)}T00:00:00Z`,
      ...extra,
    }),
    "utf8",
  );
}

function fetchServing(files: Record<string, Buffer | string>): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    const name = url.split("/").pop() ?? "";
    const body = files[name];
    if (body === undefined) {
      return new Response("not found", { status: 404 });
    }
    return new Response(typeof body === "string" ? body : new Uint8Array(body), { status: 200 });
  }) as typeof fetch;
}

const tempDirs: string[] = [];
function makeTempHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "codegate-content-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  resetContentStoreCache();
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
});

describe("bundle signature verification", () => {
  it("accepts a valid signature and rejects tampering and wrong keys", async () => {
    const { publicPem, privatePem } = await testKeys();
    const bundleBytes = makeBundle("2026.08.01");
    const signature = signBundle(bundleBytes, privatePem);

    expect(verifyBundleSignature(bundleBytes, signature, publicPem)).toBe(true);

    const tampered = Buffer.from(bundleBytes.toString("utf8").replace("2026.08.01", "9999.01.01"));
    expect(verifyBundleSignature(tampered, signature, publicPem)).toBe(false);

    const otherKey = generateKeyPairSync("ed25519").publicKey.export({
      type: "spki",
      format: "pem",
    }) as string;
    expect(verifyBundleSignature(bundleBytes, signature, otherKey)).toBe(false);

    expect(verifyBundleSignature(bundleBytes, "not-base64!!!", publicPem)).toBe(false);
  });

  it("rejects malformed bundles with clear reasons", () => {
    expect(() => parseContentBundle(Buffer.from("nonsense"))).toThrow(/not valid JSON/u);
    expect(() => parseContentBundle(Buffer.from(JSON.stringify({ schema_version: "99" })))).toThrow(
      /schema_version/u,
    );
    expect(() => parseContentBundle(Buffer.from(JSON.stringify({ schema_version: "1" })))).toThrow(
      /content_version/u,
    );
  });
});

describe("content updater", () => {
  it("installs a verified bundle, is idempotent, and prunes to two versions", async () => {
    const { privatePem } = await testKeys();
    const home = makeTempHome();
    const deps = { homeDir: () => home };

    for (const version of ["2026.08.01", "2026.08.02", "2026.08.03"]) {
      const bundleBytes = makeBundle(version);
      const result = await updateContent(
        {
          ...deps,
          fetchImpl: fetchServing({
            "codegate-content.json": bundleBytes,
            "codegate-content.json.sig": signBundle(bundleBytes, privatePem),
          }),
        },
        { baseUrl: "https://example.com/feed" },
      );
      expect(result.changed).toBe(true);
      expect(result.version).toBe(version);
      resetContentStoreCache();
    }

    expect(getActiveContentVersion(deps)).toBe("2026.08.03");
    const installed = listInstalledContentVersions(deps).map((entry) => entry.version);
    expect(installed).toEqual(["2026.08.03", "2026.08.02"]);

    const sameBytes = makeBundle("2026.08.03");
    const unchanged = await updateContent(
      {
        ...deps,
        fetchImpl: fetchServing({
          "codegate-content.json": sameBytes,
          "codegate-content.json.sig": signBundle(sameBytes, privatePem),
        }),
      },
      { baseUrl: "https://example.com/feed" },
    );
    expect(unchanged.changed).toBe(false);
  });

  it("rejects tampered downloads and installs nothing", async () => {
    const { privatePem } = await testKeys();
    const home = makeTempHome();
    const bundleBytes = makeBundle("2026.08.05");
    const signature = signBundle(bundleBytes, privatePem);
    const tampered = Buffer.from(bundleBytes.toString("utf8").replace("2026.08.05", "2026.08.06"));

    await expect(
      updateContent(
        {
          homeDir: () => home,
          fetchImpl: fetchServing({
            "codegate-content.json": tampered,
            "codegate-content.json.sig": signature,
          }),
        },
        { baseUrl: "https://example.com/feed" },
      ),
    ).rejects.toThrow(/signature verification failed/u);

    expect(getActiveContentVersion({ homeDir: () => home })).toBeNull();
  });

  it("refuses to fetch without a publisher key", async () => {
    const fetchSpy = vi.fn();
    await expect(
      updateContent({
        homeDir: () => makeTempHome(),
        publisherKeyPem: null,
        fetchImpl: fetchSpy as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/publisher key/u);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects non-https URLs", async () => {
    await expect(
      updateContent({ homeDir: () => makeTempHome() }, { baseUrl: "http://example.com/feed" }),
    ).rejects.toThrow(/https/u);
  });

  it("checks without installing and rolls back to the previous version", async () => {
    const { privatePem } = await testKeys();
    const home = makeTempHome();
    const deps = { homeDir: () => home };

    for (const version of ["2026.08.01", "2026.08.02"]) {
      const bundleBytes = makeBundle(version);
      await updateContent(
        {
          ...deps,
          fetchImpl: fetchServing({
            "codegate-content.json": bundleBytes,
            "codegate-content.json.sig": signBundle(bundleBytes, privatePem),
          }),
        },
        { baseUrl: "https://example.com/feed" },
      );
      resetContentStoreCache();
    }

    const newer = makeBundle("2026.08.09");
    const checked = await checkContentUpdate(
      {
        ...deps,
        fetchImpl: fetchServing({
          "codegate-content.json": newer,
          "codegate-content.json.sig": signBundle(newer, privatePem),
        }),
      },
      { baseUrl: "https://example.com/feed" },
    );
    expect(checked).toEqual({
      currentVersion: "2026.08.02",
      remoteVersion: "2026.08.09",
      updateAvailable: true,
    });
    expect(getActiveContentVersion(deps)).toBe("2026.08.02");

    const rolledBack = rollbackContent(deps);
    expect(rolledBack.version).toBe("2026.08.01");
    expect(getActiveContentVersion(deps)).toBe("2026.08.01");

    expect(() => rollbackContent({ homeDir: () => makeTempHome() })).toThrow(/No previous/u);
  });
});

describe("content store loading", () => {
  it("loads only verified bundles and degrades to null on tampering", async () => {
    const { privatePem } = await testKeys();
    const home = makeTempHome();
    const deps = { homeDir: () => home };
    const bundleBytes = makeBundle("2026.08.02", {
      override_phrases: [{ phrase: "phrase from feed", language: "xx" }],
    });

    await updateContent(
      {
        ...deps,
        fetchImpl: fetchServing({
          "codegate-content.json": bundleBytes,
          "codegate-content.json.sig": signBundle(bundleBytes, privatePem),
        }),
      },
      { baseUrl: "https://example.com/feed" },
    );
    resetContentStoreCache();

    const bundle = loadActiveContentBundle(deps);
    expect(bundle?.content_version).toBe("2026.08.02");
    expect(bundle?.override_phrases?.[0]?.phrase).toBe("phrase from feed");

    // Explicit null key: fail closed.
    resetContentStoreCache();
    expect(loadActiveContentBundle({ ...deps, publisherKeyPem: null })).toBeNull();

    // Cold start: nothing installed.
    resetContentStoreCache();
    expect(loadActiveContentBundle({ homeDir: () => makeTempHome() })).toBeNull();
  });
});

describe("known-bad feed indicators", () => {
  it("merges known_bad indicators from the verified feed", async () => {
    const { privatePem } = await testKeys();
    const home = makeTempHome();
    const deps = { homeDir: () => home };
    const bundleBytes = makeBundle("2026.08.02", {
      known_bad: {
        package_names: ["Evil-MCP-Server"],
        url_patterns: ["evil.example.com"],
      },
    });

    await updateContent(
      {
        ...deps,
        fetchImpl: fetchServing({
          "codegate-content.json": bundleBytes,
          "codegate-content.json.sig": signBundle(bundleBytes, privatePem),
        }),
      },
      { baseUrl: "https://example.com/feed" },
    );
    resetContentStoreCache();
    resetKnownBadIndicatorsCache();

    const previousHome = process.env.HOME;
    process.env.HOME = home;
    try {
      const indicators = loadKnownBadIndicators({ homeDir: () => home });
      expect(indicators.packageNames.has("evil-mcp-server")).toBe(true);
      expect(indicators.urlPatterns).toContain("evil.example.com");
    } finally {
      process.env.HOME = previousHome;
      resetKnownBadIndicatorsCache();
    }
  });
});

describe("knowledge base resolution order", () => {
  const KB_ENTRY = {
    tool: "feed-tool",
    version_range: ">=1.0.0",
    config_paths: [
      {
        path: ".feedtool/config.json",
        scope: "project",
        format: "json",
        risk_surface: ["mcp_servers"],
      },
    ],
  };

  function withTempHome<T>(home: string, run: () => T): T {
    const previousHome = process.env.HOME;
    process.env.HOME = home;
    try {
      return run();
    } finally {
      process.env.HOME = previousHome;
      resetContentStoreCache();
    }
  }

  it("prefers valid feed KB entries and falls back to bundled on invalid ones", async () => {
    const { privatePem } = await testKeys();
    const home = makeTempHome();
    const deps = { homeDir: () => home };

    const validBundle = makeBundle("2026.08.02", {
      kb_schema_version: "feed-kb-1",
      kb_entries: [KB_ENTRY],
    });
    await updateContent(
      {
        ...deps,
        fetchImpl: fetchServing({
          "codegate-content.json": validBundle,
          "codegate-content.json.sig": signBundle(validBundle, privatePem),
        }),
      },
      { baseUrl: "https://example.com/feed" },
    );
    resetContentStoreCache();

    const feedKb = withTempHome(home, () => loadKnowledgeBase());
    expect(feedKb.schemaVersion).toBe("feed-kb-1");
    expect(feedKb.entries).toHaveLength(1);
    expect(feedKb.entries[0]?.tool).toBe("feed-tool");

    const invalidBundle = makeBundle("2026.08.03", {
      kb_entries: [{ tool: "broken" }],
    });
    await updateContent(
      {
        ...deps,
        fetchImpl: fetchServing({
          "codegate-content.json": invalidBundle,
          "codegate-content.json.sig": signBundle(invalidBundle, privatePem),
        }),
      },
      { baseUrl: "https://example.com/feed" },
    );
    resetContentStoreCache();

    const fallbackKb = withTempHome(home, () => loadKnowledgeBase());
    expect(fallbackKb.entries.length).toBeGreaterThan(5);
    expect(fallbackKb.entries.some((entry) => entry.tool === "claude-code")).toBe(true);
  });
});
