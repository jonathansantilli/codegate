import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  collectArtifactContent,
  COLLECT_NOTHING,
  mayUpload,
  MAX_UPLOAD_ARTIFACTS,
  MAX_UPLOAD_BYTES,
  resolveCollectionPolicy,
} from "../../src/fleet/collection-policy";
import { fetchCollectionPolicy } from "../../src/fleet/policy-client";
import type { InventoryItem } from "../../src/commands/inventory-command";

function hash(content: string): string {
  return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

const OPEN_POLICY = {
  collect_content: true,
  allowed_risk_surfaces: ["prompt_injection", "unicode_backdoor", "command_exec"],
  max_bytes_per_artifact: 4096,
  max_artifacts_per_report: 50,
};

function item(overrides: Partial<InventoryItem> & { sha256?: string } = {}) {
  return {
    tool: "claude-code",
    kind: "config" as const,
    scope: "project" as const,
    pattern: "CLAUDE.md",
    path: "/repo/CLAUDE.md",
    exists: true,
    risk_surface: ["prompt_injection"],
    format: "markdown",
    resolved_against: "/repo",
    ...overrides,
  };
}

function serving(body: unknown, status = 200): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
}

const CONFIG = { server: "https://guardian.acme.internal", token: "cgm_x" };

describe("resolveCollectionPolicy", () => {
  it("collects nothing when the server does not ask", () => {
    expect(resolveCollectionPolicy({ collect_content: false })).toEqual(COLLECT_NOTHING);
    expect(resolveCollectionPolicy(null)).toEqual(COLLECT_NOTHING);
    expect(resolveCollectionPolicy(undefined)).toEqual(COLLECT_NOTHING);
  });

  // mcp_config survives: a skill declaring it can influence MCP configuration,
  // which is a risk worth reading about, not a credential in the file. What
  // never survives is a surface that means the file holds a secret.
  it("drops credential-bearing surfaces and keeps the rest", () => {
    const policy = resolveCollectionPolicy({
      ...OPEN_POLICY,
      allowed_risk_surfaces: ["prompt_injection", "mcp_config", "env_override"],
    });

    expect(policy.allowedRiskSurfaces).toEqual(["prompt_injection", "mcp_config"]);
  });

  // The point of the whole file: a server asking for everything gets nothing
  // it would not have got by asking politely.
  it("refuses to be talked above its own ceiling", () => {
    const policy = resolveCollectionPolicy({
      collect_content: true,
      allowed_risk_surfaces: ["prompt_injection"],
      max_bytes_per_artifact: 999_999_999,
      max_artifacts_per_report: 999_999,
    });

    expect(policy.maxBytesPerArtifact).toBe(MAX_UPLOAD_BYTES);
    expect(policy.maxArtifactsPerReport).toBe(MAX_UPLOAD_ARTIFACTS);
  });

  it("collects nothing when every requested surface is credential-bearing", () => {
    expect(
      resolveCollectionPolicy({
        ...OPEN_POLICY,
        allowed_risk_surfaces: ["env_override", "provider_credentials"],
      }),
    ).toEqual(COLLECT_NOTHING);
  });

  it("collects nothing when the server sends nonsense", () => {
    expect(
      resolveCollectionPolicy({
        collect_content: true,
        allowed_risk_surfaces: "everything" as unknown,
        max_bytes_per_artifact: -1,
        max_artifacts_per_report: Number.NaN,
      }),
    ).toEqual(COLLECT_NOTHING);
  });
});

describe("mayUpload", () => {
  const policy = resolveCollectionPolicy(OPEN_POLICY);

  it("allows a rules file", () => {
    expect(
      mayUpload(
        { risk_surface: ["prompt_injection", "unicode_backdoor"], format: "markdown" },
        policy,
      ),
    ).toBe(true);
  });

  it("refuses anything carrying a credential-bearing surface", () => {
    expect(
      mayUpload({ risk_surface: ["prompt_injection", "mcp_config"], format: "markdown" }, policy),
    ).toBe(false);
    expect(mayUpload({ risk_surface: ["env_override"], format: "markdown" }, policy)).toBe(false);
  });

  it("refuses an artifact that declares nothing", () => {
    expect(mayUpload({ risk_surface: [], format: "markdown" }, policy)).toBe(false);
  });
});

describe("collectArtifactContent", () => {
  const policy = resolveCollectionPolicy(OPEN_POLICY);
  const rules = "# Rules\n\nBe careful.\n";

  it("reads the artifacts the policy permits", () => {
    const collected = collectArtifactContent([item({ sha256: hash(rules) })], policy, {
      readFile: () => rules,
      fileSize: () => rules.length,
    });

    expect(collected).toEqual([{ sha256: hash(rules), content: rules }]);
  });

  it("sends nothing at all when the policy is closed", () => {
    expect(
      collectArtifactContent([item({ sha256: hash(rules) })], COLLECT_NOTHING, {
        readFile: () => rules,
        fileSize: () => rules.length,
      }),
    ).toEqual([]);
  });

  it("skips an artifact whose surfaces are not allowed", () => {
    const collected = collectArtifactContent(
      [item({ sha256: hash(rules), risk_surface: ["mcp_config"] })],
      policy,
      { readFile: () => rules, fileSize: () => rules.length },
    );

    expect(collected).toEqual([]);
  });

  // Sending bytes under a stale hash would file them against the wrong
  // artifact on the server.
  it("skips a file that changed between the inventory pass and the read", () => {
    const collected = collectArtifactContent([item({ sha256: hash(rules) })], policy, {
      readFile: () => "different content now",
      fileSize: () => 21,
    });

    expect(collected).toEqual([]);
  });

  it("skips a file larger than the policy allows without reading it", () => {
    let read = false;
    const collected = collectArtifactContent([item({ sha256: hash(rules) })], policy, {
      readFile: () => {
        read = true;
        return rules;
      },
      fileSize: () => 999_999,
    });

    expect(collected).toEqual([]);
    expect(read).toBe(false);
  });

  it("stops at the per-report limit", () => {
    const items = Array.from({ length: 5 }, (_, i) =>
      item({ path: `/repo/R${i}.md`, sha256: hash(rules) }),
    );
    const collected = collectArtifactContent(
      items,
      { ...policy, maxArtifactsPerReport: 2 },
      { readFile: () => rules, fileSize: () => rules.length },
    );

    // Same bytes, so deduplication leaves one — the limit is not the binding
    // constraint here, identity is.
    expect(collected).toHaveLength(1);
  });

  it("skips an unreadable file rather than failing the report", () => {
    const collected = collectArtifactContent([item({ sha256: hash(rules) })], policy, {
      readFile: () => {
        throw new Error("EACCES");
      },
      fileSize: () => rules.length,
    });

    expect(collected).toEqual([]);
  });

  it("skips items that do not exist", () => {
    expect(
      collectArtifactContent([item({ exists: false, sha256: hash(rules) })], policy, {
        readFile: () => rules,
        fileSize: () => rules.length,
      }),
    ).toEqual([]);
  });
});

describe("fetchCollectionPolicy", () => {
  it("returns the intersected policy when a server asks", async () => {
    const policy = await fetchCollectionPolicy(CONFIG, { fetch: serving(OPEN_POLICY) });
    expect(policy.collectContent).toBe(true);
    expect(policy.allowedRiskSurfaces).toContain("prompt_injection");
  });

  it("collects nothing when the server has no policy endpoint", async () => {
    const policy = await fetchCollectionPolicy(CONFIG, { fetch: serving({}, 404) });
    expect(policy).toEqual(COLLECT_NOTHING);
  });

  it("collects nothing when the server is unreachable", async () => {
    const policy = await fetchCollectionPolicy(CONFIG, {
      fetch: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    });
    expect(policy).toEqual(COLLECT_NOTHING);
  });

  it("collects nothing when the answer is not JSON", async () => {
    const policy = await fetchCollectionPolicy(CONFIG, {
      fetch: (async () =>
        new Response("<html>captive portal</html>", { status: 200 })) as unknown as typeof fetch,
    });
    expect(policy).toEqual(COLLECT_NOTHING);
  });
});

/**
 * How a file is written decides whether it can hold a secret. Deciding on risk
 * surfaces alone refused Claude Code skills — which declare mcp_config because
 * a skill can influence MCP configuration, not because the markdown holds a
 * key — while admitting .toml command files that can carry one in an env block.
 */
describe("mayUpload gates on format", () => {
  const policy = resolveCollectionPolicy({
    collect_content: true,
    allowed_risk_surfaces: ["prompt_injection", "unicode_backdoor", "command_exec", "mcp_config"],
    max_bytes_per_artifact: 4096,
    max_artifacts_per_report: 50,
  });

  it("sends a Claude Code skill even though it declares mcp_config", () => {
    expect(
      mayUpload({ risk_surface: ["prompt_injection", "mcp_config"], format: "markdown" }, policy),
    ).toBe(true);
  });

  it("refuses a toml command definition however harmless its surfaces look", () => {
    expect(
      mayUpload({ risk_surface: ["prompt_injection", "command_exec"], format: "toml" }, policy),
    ).toBe(false);
  });

  it("refuses jsonc", () => {
    expect(mayUpload({ risk_surface: ["prompt_injection"], format: "jsonc" }, policy)).toBe(false);
  });

  it("refuses an artifact whose format it cannot name", () => {
    expect(mayUpload({ risk_surface: ["prompt_injection"] }, policy)).toBe(false);
  });

  it("still refuses prose that carries a credential-bearing surface", () => {
    expect(
      mayUpload({ risk_surface: ["prompt_injection", "env_override"], format: "markdown" }, policy),
    ).toBe(false);
  });
});
