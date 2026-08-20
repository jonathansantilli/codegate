import type { Finding } from "../types/finding.js";
import type { RegistryPackageMetadata } from "./registry-client.js";

export interface RegistryHeuristicsOptions {
  recentPublishDays?: number;
  now?: () => number;
}

const DEFAULT_RECENT_PUBLISH_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractRegistryMetadata(metadata: unknown): RegistryPackageMetadata | null {
  if (!isRecord(metadata) || !isRecord(metadata.registry)) {
    return null;
  }
  const registry = metadata.registry;
  if (typeof registry.kind !== "string" || typeof registry.name !== "string") {
    return null;
  }
  return registry as unknown as RegistryPackageMetadata;
}

function makeFinding(
  resourceId: string,
  registry: RegistryPackageMetadata,
  ruleId: string,
  severity: Finding["severity"],
  description: string,
): Finding {
  return {
    rule_id: ruleId,
    finding_id: `${ruleId.toUpperCase().replaceAll("-", "_")}-${resourceId}`,
    severity,
    category: "COMMAND_EXEC",
    layer: "L3",
    file_path: resourceId,
    location: { field: `registry.${registry.name}` },
    description,
    affected_tools: [],
    cve: null,
    owasp: ["ASI05"],
    cwe: "CWE-829",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    metadata: {
      sources: [resourceId],
      risk_tags: ["registry", "supply-chain"],
      origin: "registry-findings",
    },
    suppressed: false,
  };
}

/** Derive supply-chain findings from registry metadata fetched by the deep scan. */
export function deriveRegistryFindings(
  resourceId: string,
  metadata: unknown,
  options: RegistryHeuristicsOptions = {},
): Finding[] {
  const registry = extractRegistryMetadata(metadata);
  if (!registry) {
    return [];
  }

  const findings: Finding[] = [];

  if (registry.installScripts.length > 0) {
    findings.push(
      makeFinding(
        resourceId,
        registry,
        "package-install-scripts",
        "HIGH",
        `Package "${registry.name}" declares npm lifecycle scripts (${registry.installScripts.join(
          ", ",
        )}) that execute code at install time.`,
      ),
    );
  }

  if (registry.deprecated) {
    findings.push(
      makeFinding(
        resourceId,
        registry,
        "package-deprecated",
        "MEDIUM",
        `Package "${registry.name}" is marked deprecated/yanked by its registry: ${registry.deprecated}`,
      ),
    );
  }

  const recentDays = options.recentPublishDays ?? DEFAULT_RECENT_PUBLISH_DAYS;
  if (registry.latestPublishedAt) {
    const publishedAt = Date.parse(registry.latestPublishedAt);
    const now = options.now ? options.now() : Date.now();
    if (Number.isFinite(publishedAt) && now - publishedAt < recentDays * DAY_MS) {
      findings.push(
        makeFinding(
          resourceId,
          registry,
          "package-recently-published",
          "MEDIUM",
          `Package "${registry.name}" version ${registry.latestVersion ?? "?"} was published within ` +
            `the last ${recentDays} days. Fresh releases are the window for compromised-package attacks.`,
        ),
      );
    }
  }

  return findings;
}
