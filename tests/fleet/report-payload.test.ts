import { createHash } from "node:crypto";
import { resolve as resolvePath } from "node:path";
import { describe, expect, it } from "vitest";
import type { InventoryItem, InventorySummary } from "../../src/commands/inventory-command";
import {
  buildReportPayload,
  hashArtifact,
  toReportFinding,
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

describe("finding paths", () => {
  // The fixtures are written POSIX-style for readability, but the code
  // resolves them with the host's own rules — on Windows "/repo" becomes
  // "D:\\repo". Deriving the expectation the same way keeps this a test of
  // the resolution behaviour rather than of the runner's platform.
  const SCAN_ROOT = resolvePath("/repo");
  const SETTINGS_PATH = resolvePath(SCAN_ROOT, ".claude/settings.json");

  const finding = {
    finding_id: "f-1",
    rule_id: "env-base-url-override",
    severity: "CRITICAL",
    file_path: ".claude/settings.json",
    location: { line: 3, column: 28 },
    description: "Agent traffic redirected to a third party",
    owasp: [],
    suppressed: false,
  } as unknown as import("../../src/types/finding").Finding;

  const inventory = {
    kb_version: "2026-08-20",
    tools: [],
    items: [
      {
        tool: "claude-code",
        kind: "config" as const,
        scope: "user" as const,
        pattern: ".claude/settings.json",
        path: SETTINGS_PATH,
        exists: true,
        risk_surface: [],
        resolved_against: SCAN_ROOT,
      },
    ],
  };

  // The scanner reports paths relative to the scan root; inventory paths are
  // absolute. This mismatch silently stripped every finding's hash until an
  // end-to-end run exposed it.
  it("resolves a scan-relative finding path against the scan root to find its hash", () => {
    const payload = buildReportPayload(
      {
        machineId: "m",
        host: { hostname: "h" },
        inventory,
        findings: [finding],
        findingPathBase: SCAN_ROOT,
        collectedAt: new Date("2026-08-22T12:00:00Z"),
      },
      { readFile: () => CONTENT, fileSize: () => CONTENT.length },
    );

    expect(payload.findings?.[0].sha256).toBe(EXPECTED);
    expect(payload.findings?.[0].file_path).toBe(SETTINGS_PATH);
  });

  it("leaves an already-absolute finding path alone", () => {
    const payload = buildReportPayload(
      {
        machineId: "m",
        host: { hostname: "h" },
        inventory,
        findings: [{ ...finding, file_path: SETTINGS_PATH } as typeof finding],
        findingPathBase: "/somewhere/else",
        collectedAt: new Date("2026-08-22T12:00:00Z"),
      },
      { readFile: () => CONTENT, fileSize: () => CONTENT.length },
    );

    expect(payload.findings?.[0].file_path).toBe(SETTINGS_PATH);
    expect(payload.findings?.[0].sha256).toBe(EXPECTED);
  });

  it("sends the finding without a hash when no artifact matches", () => {
    const payload = buildReportPayload(
      {
        machineId: "m",
        host: { hostname: "h" },
        inventory: { ...inventory, items: [] },
        findings: [finding],
        findingPathBase: SCAN_ROOT,
        collectedAt: new Date("2026-08-22T12:00:00Z"),
      },
      { readFile: () => CONTENT, fileSize: () => CONTENT.length },
    );

    expect(payload.findings).toHaveLength(1);
    expect(payload.findings?.[0].sha256).toBeUndefined();
  });
});

/**
 * User scope is where skills and global configs live, which is most of what
 * this product looks at — and every finding on one of them arrived at the
 * server with no content hash until an end-to-end run showed the console
 * listing a skill with a HIGH finding as "Clean".
 */
describe("finding paths reported with a literal tilde", () => {
  const HOME = resolvePath("/home/u");
  const SKILL = resolvePath(HOME, ".claude/skills/deploy-helper/SKILL.md");
  const HASH = `sha256:${"a".repeat(64)}`;

  function tildeFinding(filePath: string) {
    return {
      finding_id: "f-1",
      rule_id: "rule-file-suspicious-instruction",
      severity: "HIGH",
      file_path: filePath,
      location: { line: 8 },
      description: "Rule file contains suspicious instruction pattern",
      owasp: [],
      suppressed: false,
    } as unknown as import("../../src/types/finding").Finding;
  }

  const hashes = new Map([[SKILL.split(/[\\/]/).join("/"), HASH]]);

  it("expands ~ so the finding matches the artifact it is about", () => {
    const reported = toReportFinding(
      tildeFinding("~/.claude/skills/deploy-helper/SKILL.md"),
      hashes,
      resolvePath("/repo"),
      HOME,
    );

    expect(reported.sha256).toBe(HASH);
    expect(reported.file_path).toBe(SKILL);
  });

  // The bug was not only the missing hash: ~ is not absolute, so the path was
  // joined onto the scan root and the console displayed "/repo/~/.claude/...".
  it("does not join a tilde path onto the scan root", () => {
    const reported = toReportFinding(
      tildeFinding("~/.claude/settings.json"),
      new Map(),
      resolvePath("/repo"),
      HOME,
    );

    expect(reported.file_path).not.toContain("~");
    expect(reported.file_path).toBe(resolvePath(HOME, ".claude/settings.json"));
  });

  it("expands a bare ~", () => {
    expect(toReportFinding(tildeFinding("~"), new Map(), undefined, HOME).file_path).toBe(HOME);
  });

  // A file genuinely called ~notes.md is a file, not a home directory.
  it("leaves a leading tilde that is part of a filename alone", () => {
    const reported = toReportFinding(
      tildeFinding("~notes.md"),
      new Map(),
      resolvePath("/repo"),
      HOME,
    );

    expect(reported.file_path).toBe(resolvePath("/repo", "~notes.md"));
  });

  it("still resolves a scan-relative path against the scan root", () => {
    const reported = toReportFinding(
      tildeFinding(".claude/settings.json"),
      new Map(),
      resolvePath("/repo"),
      HOME,
    );

    expect(reported.file_path).toBe(resolvePath("/repo", ".claude/settings.json"));
  });

  it("leaves an already-absolute path alone", () => {
    const reported = toReportFinding(tildeFinding(SKILL), hashes, resolvePath("/repo"), HOME);
    expect(reported.file_path).toBe(SKILL);
    expect(reported.sha256).toBe(HASH);
  });
});
