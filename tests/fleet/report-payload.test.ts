import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { InventoryItem, InventorySummary } from "../../src/commands/inventory-command";
import {
  buildReportPayload,
  hashArtifact,
  withContentHashes,
} from "../../src/fleet/report-payload";

function item(overrides: Partial<InventoryItem> = {}): InventoryItem {
  return {
    tool: "claude-code",
    kind: "skill",
    scope: "user",
    pattern: ".claude/skills/*/SKILL.md",
    path: "/home/u/.claude/skills/podcast/SKILL.md",
    exists: true,
    risk_surface: ["prompt-injection"],
    resolved_against: "/home/u",
    ...overrides,
  };
}

function summary(items: InventoryItem[]): InventorySummary {
  return {
    kb_version: "2026-08-20",
    tools: [{ name: "claude-code", version_range: ">=1" }],
    items,
  };
}

const CONTENT = "malicious skill body";
const EXPECTED = `sha256:${createHash("sha256").update(CONTENT, "utf8").digest("hex")}`;

describe("hashArtifact", () => {
  // Must match the known-bad detector byte for byte, or a reported hash can
  // never be compared against a content-feed indicator.
  it("hashes utf-8 content the way the known-bad detector does", () => {
    const hash = hashArtifact("/any", { readFile: () => CONTENT, fileSize: () => CONTENT.length });
    expect(hash).toBe(EXPECTED);
  });

  it("returns undefined for an unreadable file rather than guessing", () => {
    const hash = hashArtifact("/gone", {
      readFile: () => {
        throw new Error("ENOENT");
      },
      fileSize: () => 10,
    });
    expect(hash).toBeUndefined();
  });

  it("skips a file too large to be a config or a skill", () => {
    const hash = hashArtifact("/big", { readFile: () => CONTENT, fileSize: () => 9 * 1024 * 1024 });
    expect(hash).toBeUndefined();
  });
});

describe("withContentHashes", () => {
  it("adds a hash to every artifact present on disk", () => {
    const [hashed] = withContentHashes([item()], {
      readFile: () => CONTENT,
      fileSize: () => CONTENT.length,
    });
    expect(hashed.sha256).toBe(EXPECTED);
  });

  // An absent file has no bytes; claiming a hash for one would be a lie.
  it("leaves an absent artifact unhashed", () => {
    const [unhashed] = withContentHashes([item({ exists: false })], {
      readFile: () => CONTENT,
      fileSize: () => CONTENT.length,
    });
    expect(unhashed.sha256).toBeUndefined();
  });

  it("keeps an item whose hash could not be computed", () => {
    const hashed = withContentHashes([item()], {
      readFile: () => {
        throw new Error("EACCES");
      },
      fileSize: () => 10,
    });
    expect(hashed).toHaveLength(1);
    expect(hashed[0].sha256).toBeUndefined();
    expect(hashed[0].path).toBe(item().path);
  });

  it("preserves every field the CLI produced", () => {
    const [hashed] = withContentHashes([item()], {
      readFile: () => CONTENT,
      fileSize: () => CONTENT.length,
    });
    expect(hashed.tool).toBe("claude-code");
    expect(hashed.risk_surface).toEqual(["prompt-injection"]);
    expect(hashed.resolved_against).toBe("/home/u");
  });
});

describe("buildReportPayload", () => {
  const base = {
    machineId: "machine-1",
    agentVersion: "1.1.0",
    host: { hostname: "dev-laptop-01", platform: "darwin", username: "jsantilli" },
    inventory: summary([item()]),
    collectedAt: new Date("2026-08-22T12:00:00.000Z"),
  };
  const deps = { readFile: () => CONTENT, fileSize: () => CONTENT.length };

  it("carries agent identity, host facts and an ISO timestamp", () => {
    const payload = buildReportPayload(base, deps);
    expect(payload.agent).toEqual({ machineId: "machine-1", version: "1.1.0" });
    expect(payload.host.hostname).toBe("dev-laptop-01");
    expect(payload.collectedAt).toBe("2026-08-22T12:00:00.000Z");
  });

  it("forwards the inventory summary unchanged apart from hashes", () => {
    const payload = buildReportPayload(base, deps);
    expect(payload.inventory.kb_version).toBe("2026-08-20");
    expect(payload.inventory.tools).toEqual([{ name: "claude-code", version_range: ">=1" }]);
    expect(payload.inventory.items[0].sha256).toBe(EXPECTED);
  });

  it("omits the agent version when it is not known", () => {
    const payload = buildReportPayload({ ...base, agentVersion: undefined }, deps);
    expect(payload.agent).toEqual({ machineId: "machine-1" });
  });

  it("reports an empty inventory without inventing items", () => {
    const payload = buildReportPayload({ ...base, inventory: summary([]) }, deps);
    expect(payload.inventory.items).toEqual([]);
  });
});
