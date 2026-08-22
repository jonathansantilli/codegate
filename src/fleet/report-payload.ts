import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import type { InventoryItem, InventorySummary } from "../commands/inventory-command.js";
import type { Finding } from "../types/finding.js";

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

/** A finding narrowed to what the server stores; the scanner's own shape. */
export interface ReportFinding {
  finding_id: string;
  rule_id: string;
  fingerprint?: string;
  severity: string;
  category?: string;
  layer?: string;
  file_path?: string;
  sha256?: string;
  line?: number;
  column?: number;
  description: string;
  evidence?: string;
  owasp: string[];
  cwe?: string;
  confidence?: string;
  fixable?: boolean;
  suppressed?: boolean;
}

export interface ReportPayload {
  agent: { machineId: string; version?: string };
  host: HostFacts;
  collectedAt: string;
  inventory: InventorySummary;
  /**
   * Omitted when no scan ran. Omitted is not the same as empty: an empty list
   * asserts the machine is clean, and the server treats the two differently.
   */
  findings?: ReportFinding[];
}

export interface BuildReportInput {
  machineId: string;
  agentVersion?: string;
  host: HostFacts;
  inventory: InventorySummary;
  findings?: Finding[];
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

/**
 * Narrows a scanner finding to the wire shape, carrying the hash of the file
 * it sits on so the server can tie it to an artifact variant rather than to a
 * path that differs between machines.
 */
export function toReportFinding(finding: Finding, hashByPath: Map<string, string>): ReportFinding {
  const sha256 = finding.file_path ? hashByPath.get(finding.file_path) : undefined;

  return {
    finding_id: finding.finding_id,
    rule_id: finding.rule_id,
    ...(finding.fingerprint ? { fingerprint: finding.fingerprint } : {}),
    severity: finding.severity,
    category: finding.category,
    layer: finding.layer,
    ...(finding.file_path ? { file_path: finding.file_path } : {}),
    ...(sha256 ? { sha256 } : {}),
    ...(finding.location?.line !== undefined ? { line: finding.location.line } : {}),
    ...(finding.location?.column !== undefined ? { column: finding.location.column } : {}),
    description: finding.description,
    ...(finding.evidence ? { evidence: finding.evidence } : {}),
    owasp: finding.owasp ?? [],
    cwe: finding.cwe,
    confidence: finding.confidence,
    fixable: finding.fixable,
    suppressed: finding.suppressed,
  };
}

export function buildReportPayload(input: BuildReportInput, deps: HashDeps = {}): ReportPayload {
  const items = withContentHashes(input.inventory.items, deps);
  const hashByPath = new Map(
    items
      .filter((item): item is InventoryItem & { sha256: string } => item.sha256 !== undefined)
      .map((item) => [item.path, item.sha256]),
  );

  return {
    agent: {
      machineId: input.machineId,
      ...(input.agentVersion ? { version: input.agentVersion } : {}),
    },
    host: input.host,
    collectedAt: input.collectedAt.toISOString(),
    inventory: { ...input.inventory, items },
    ...(input.findings
      ? { findings: input.findings.map((finding) => toReportFinding(finding, hashByPath)) }
      : {}),
  };
}
