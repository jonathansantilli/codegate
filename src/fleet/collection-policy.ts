import { readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import type { InventoryItem } from "../commands/inventory-command.js";

/**
 * What this agent is prepared to send, whatever a server asks for.
 *
 * A Guardian server publishes a collection policy, and this machine reads it.
 * That makes the server an input, and inputs from the network are not
 * instructions: the server names what it would accept, and everything below
 * decides what we are willing to offer. The narrower of the two wins, always.
 *
 * The reason this file exists rather than trusting the policy: the server is
 * reached over the network by a program running on a developer's laptop, and
 * the interesting failure is not a bug — it is a Guardian that has been taken
 * over, or a DNS answer that is not the Guardian anyone enrolled with. Such a
 * server can say "send me everything". This list is why that does not work.
 *
 * The same reasoning already applies elsewhere: an enrolling server cannot
 * make us write an unbounded token to disk. This is the same rule for a
 * bigger prize.
 */

/**
 * Surfaces whose files are prose: instructions, hidden characters in
 * instructions, and shell commands written into instructions. Skills and rules
 * files carry these.
 *
 * Everything else the knowledge base declares sits on configuration —
 * mcp_config, env_override, ide_settings, provider_credentials, secret_leak,
 * channel_token — and configuration is where API keys live. Allowlisted rather
 * than denylisted so that a surface added to the knowledge base tomorrow is
 * refused until somebody widens this deliberately.
 */
export const UPLOADABLE_RISK_SURFACES: readonly string[] = [
  "prompt_injection",
  "unicode_backdoor",
  "command_exec",
];

/** No server may raise these, whatever its policy says. */
export const MAX_UPLOAD_BYTES = 262_144;
export const MAX_UPLOAD_ARTIFACTS = 200;

/** The policy as a Guardian publishes it. Every field is untrusted. */
export interface ServerCollectionPolicy {
  collect_content?: unknown;
  allowed_risk_surfaces?: unknown;
  max_bytes_per_artifact?: unknown;
  max_artifacts_per_report?: unknown;
}

export interface EffectiveCollectionPolicy {
  collectContent: boolean;
  allowedRiskSurfaces: string[];
  maxBytesPerArtifact: number;
  maxArtifactsPerReport: number;
}

/** Collect nothing. What an unreachable, unreadable or silent server gets. */
export const COLLECT_NOTHING: EffectiveCollectionPolicy = {
  collectContent: false,
  allowedRiskSurfaces: [],
  maxBytesPerArtifact: 0,
  maxArtifactsPerReport: 0,
};

function boundedNumber(value: unknown, ceiling: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return 0;
  }
  return Math.min(Math.floor(value), ceiling);
}

/**
 * Intersects a server's policy with this agent's ceiling.
 *
 * Everything here narrows. There is deliberately no branch in which a value
 * from the server makes this agent send more than it would have on its own.
 */
export function resolveCollectionPolicy(
  published: ServerCollectionPolicy | null | undefined,
): EffectiveCollectionPolicy {
  if (!published || published.collect_content !== true) {
    return COLLECT_NOTHING;
  }

  const requested = Array.isArray(published.allowed_risk_surfaces)
    ? published.allowed_risk_surfaces.filter((s): s is string => typeof s === "string")
    : [];
  const allowedRiskSurfaces = requested.filter((s) => UPLOADABLE_RISK_SURFACES.includes(s));

  const maxBytesPerArtifact = boundedNumber(published.max_bytes_per_artifact, MAX_UPLOAD_BYTES);
  const maxArtifactsPerReport = boundedNumber(
    published.max_artifacts_per_report,
    MAX_UPLOAD_ARTIFACTS,
  );

  // A policy that survives the intersection with nothing left is a policy that
  // asked for nothing we will give, which is the same as asking for nothing.
  if (
    allowedRiskSurfaces.length === 0 ||
    maxBytesPerArtifact === 0 ||
    maxArtifactsPerReport === 0
  ) {
    return COLLECT_NOTHING;
  }

  return {
    collectContent: true,
    allowedRiskSurfaces,
    maxBytesPerArtifact,
    maxArtifactsPerReport,
  };
}

/** True when every surface the artifact declares is one we will send. */
export function mayUpload(
  item: Pick<InventoryItem, "risk_surface">,
  policy: EffectiveCollectionPolicy,
): boolean {
  const surfaces = item.risk_surface ?? [];
  // Nothing declared is not the same as nothing to worry about.
  if (surfaces.length === 0) {
    return false;
  }
  return surfaces.every(
    (surface) =>
      UPLOADABLE_RISK_SURFACES.includes(surface) && policy.allowedRiskSurfaces.includes(surface),
  );
}

export interface ArtifactContentEntry {
  sha256: string;
  content: string;
}

export interface CollectContentDeps {
  readFile?: (path: string) => string;
  fileSize?: (path: string) => number;
}

/**
 * Reads the artifacts the policy permits, and no others.
 *
 * Re-reads and re-hashes rather than trusting the hash computed during
 * inventory: the file may have changed in between, and sending bytes under a
 * stale hash would file them against the wrong artifact on the server.
 */
export function collectArtifactContent(
  items: (InventoryItem & { sha256?: string })[],
  policy: EffectiveCollectionPolicy,
  deps: CollectContentDeps = {},
): ArtifactContentEntry[] {
  if (!policy.collectContent) {
    return [];
  }

  const readFile = deps.readFile ?? ((p: string) => readFileSync(p, "utf8"));
  const fileSize = deps.fileSize ?? ((p: string) => statSync(p).size);

  const collected: ArtifactContentEntry[] = [];
  const seen = new Set<string>();

  for (const item of items) {
    if (collected.length >= policy.maxArtifactsPerReport) {
      break;
    }
    if (!(item.exists && item.sha256) || seen.has(item.sha256)) {
      continue;
    }
    if (!mayUpload(item, policy)) {
      continue;
    }

    try {
      // Checked before reading, so an enormous file is never pulled into
      // memory just to be discarded.
      if (fileSize(item.path) > policy.maxBytesPerArtifact) {
        continue;
      }

      const content = readFile(item.path);
      if (Buffer.byteLength(content, "utf8") > policy.maxBytesPerArtifact) {
        continue;
      }

      const sha256 = `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
      if (sha256 !== item.sha256) {
        // Changed since the inventory pass. The next report will carry it.
        continue;
      }

      seen.add(sha256);
      collected.push({ sha256, content });
    } catch {
      // Unreadable or gone between the two passes: skip it silently, exactly
      // as hashing does. A file we cannot read is not a reportable failure.
    }
  }

  return collected;
}
