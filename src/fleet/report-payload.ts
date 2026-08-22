import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import type { InventoryItem, InventorySummary } from "../commands/inventory-command.js";

/**
 * Builds the body of an agent check-in.
 *
 * The inventory summary is forwarded as the CLI produced it, so the wire
 * format cannot drift from the command; the only thing added per item is the
 * content hash, which is what the server uses as the artifact's identity.
 */

/** Files above this are not hashed: an artifact this large is not a config or a skill. */
const MAX_HASHABLE_BYTES = 8 * 1024 * 1024;

export interface HostFacts {
  hostname: string;
  platform?: string;
  osRelease?: string;
  username?: string;
}

export interface ReportPayload {
  agent: { machineId: string; version?: string };
  host: HostFacts;
  collectedAt: string;
  inventory: InventorySummary;
}

export interface BuildReportInput {
  machineId: string;
  agentVersion?: string;
  host: HostFacts;
  inventory: InventorySummary;
  collectedAt: Date;
}

export interface HashDeps {
  /** Injected for tests; defaults to reading the file from disk. */
  readFile?: (path: string) => string;
  fileSize?: (path: string) => number;
}

/**
 * Hashes an artifact exactly as the known-bad detector does — sha256 over the
 * file's UTF-8 text — so a hash reported here can be compared directly with an
 * indicator from the signed content feed.
 */
export function hashArtifact(path: string, deps: HashDeps = {}): string | undefined {
  try {
    const size = (deps.fileSize ?? ((p: string) => statSync(p).size))(path);
    if (size > MAX_HASHABLE_BYTES) {
      return undefined;
    }

    const content = (deps.readFile ?? ((p: string) => readFileSync(p, "utf8")))(path);
    return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
  } catch {
    // Unreadable, vanished between scan and hash, or not valid UTF-8. The
    // server keeps such an item but cannot group it, which is the honest
    // outcome — better than reporting a hash we are not sure of.
    return undefined;
  }
}

export function withContentHashes(
  items: InventoryItem[],
  deps: HashDeps = {},
): (InventoryItem & { sha256?: string })[] {
  return items.map((item) => {
    if (!item.exists) {
      return item;
    }
    const sha256 = hashArtifact(item.path, deps);
    return sha256 ? { ...item, sha256 } : item;
  });
}

export function buildReportPayload(input: BuildReportInput, deps: HashDeps = {}): ReportPayload {
  return {
    agent: {
      machineId: input.machineId,
      ...(input.agentVersion ? { version: input.agentVersion } : {}),
    },
    host: input.host,
    collectedAt: input.collectedAt.toISOString(),
    inventory: {
      ...input.inventory,
      items: withContentHashes(input.inventory.items, deps),
    },
  };
}
