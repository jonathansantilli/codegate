import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { isAbsolute, join as joinPath, resolve as resolvePath, sep } from "node:path";
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
  /**
   * Artifact bytes, present only when the server published a policy asking for
   * them AND this agent was willing to send them. Omitted is the normal case.
   */
  contents?: { sha256: string; content: string }[];
}

export interface BuildReportInput {
  machineId: string;
  agentVersion?: string;
  host: HostFacts;
  inventory: InventorySummary;
  findings?: Finding[];
  /**
   * Scan root that finding paths are relative to. The scanner reports paths
   * relative to what it scanned, while inventory paths are absolute, so
   * without this the two never line up and no finding gets a hash.
   */
  findingPathBase?: string;
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
/**
 * One spelling for a path, so a map key and a lookup cannot disagree.
 *
 * Inventory paths arrive as the scanner wrote them; finding paths are
 * resolved against the scan root here. Comparing those two strings directly
 * works only while they happen to be spelled identically — which they are not
 * on Windows, where `resolve` returns backslashes and a finding silently
 * loses its content hash. Both sides go through this, so the comparison is
 * between normalised forms rather than between two spellings of the same
 * file. Case is deliberately preserved: two names differing only in case are
 * two files on Linux.
 */
function pathKey(candidate: string): string {
  return resolvePath(candidate).split(sep).join("/");
}

/**
 * Expands a leading `~` to the home directory.
 *
 * The scanner reports user-scope paths with a literal tilde, and `resolve`
 * does not expand it — it treats `~` as an ordinary directory name, so
 * `~/.claude/skills/x/SKILL.md` resolved to `<scan root>/~/.claude/...`. That
 * matched no inventory item, so every user-scope finding arrived at the server
 * with no content hash and could not be tied to the artifact it was about.
 *
 * The damage was visible: the console groups artifacts by content hash, so a
 * skill carrying a HIGH finding was listed as "Clean". User scope is where
 * skills and global configs live, which is most of what this product exists
 * to look at.
 */
function expandHome(candidate: string, home: string): string {
  if (candidate === "~") {
    return home;
  }
  // Only a leading `~/` or `~\`. A file genuinely named `~foo` is left alone,
  // and `~user` is somebody else's home, which is not ours to guess at.
  if (candidate.startsWith("~/") || candidate.startsWith("~\\")) {
    return joinPath(home, candidate.slice(2));
  }
  return candidate;
}

export function toReportFinding(
  finding: Finding,
  hashByPath: Map<string, string>,
  pathBase?: string,
  home: string = homedir(),
): ReportFinding {
  // Before anything else, because `~/x` is not an absolute path as far as the
  // check below is concerned: left alone it would be joined onto the scan root
  // and produce `<scan root>/~/x`, which is not a file anywhere.
  const expanded = finding.file_path ? expandHome(finding.file_path, home) : finding.file_path;

  // The scanner reports paths relative to what it scanned; inventory paths are
  // absolute. Without resolving one against the other they never line up and
  // no finding ever gets a hash.
  const absolutePath =
    expanded && pathBase && !isAbsolute(expanded) ? resolvePath(pathBase, expanded) : expanded;
  const sha256 = absolutePath ? hashByPath.get(pathKey(absolutePath)) : undefined;

  return {
    finding_id: finding.finding_id,
    rule_id: finding.rule_id,
    ...(finding.fingerprint ? { fingerprint: finding.fingerprint } : {}),
    severity: finding.severity,
    category: finding.category,
    layer: finding.layer,
    ...(absolutePath ? { file_path: absolutePath } : {}),
    ...(sha256 ? { sha256 } : {}),
    ...(finding.location?.line !== undefined ? { line: finding.location.line } : {}),
    ...(finding.location?.column !== undefined ? { column: finding.location.column } : {}),
    description: finding.description,
    // The scanner's evidence is authoritative: it already carries the
    // offending line with its invisible characters intact, which is precisely
    // what the console needs to show.
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
      .map((item) => [pathKey(item.path), item.sha256]),
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
      ? {
          findings: input.findings.map((finding) =>
            toReportFinding(finding, hashByPath, input.findingPathBase),
          ),
        }
      : {}),
  };
}
