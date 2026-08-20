import { createHash } from "node:crypto";
import { hasKnownBadIndicators, type ResolvedKnownBadIndicators } from "../../content/known-bad.js";
import { buildFindingFingerprint } from "../../report/finding-fingerprint.js";
import type { Finding } from "../../types/finding.js";
import { collectMcpPackageLaunches, parsePackageLocator } from "./mcp-package-hygiene.js";

export interface KnownBadDetectionInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  indicators: ResolvedKnownBadIndicators;
}

export const KNOWN_BAD_MATCH_KIND = {
  FileHash: "file-hash",
  PackageName: "package-name",
  UrlPattern: "url-pattern",
} as const;
export type KnownBadMatchKind = (typeof KNOWN_BAD_MATCH_KIND)[keyof typeof KNOWN_BAD_MATCH_KIND];

export const KNOWN_BAD_RULE_ID = "known-malicious-content";

const URL_PATTERN = /https?:\/\/[^\s"'`<>)\]}]+/giu;

const MATCH_KIND_CATEGORY: Record<KnownBadMatchKind, Finding["category"]> = {
  [KNOWN_BAD_MATCH_KIND.FileHash]: "CONFIG_PRESENT",
  [KNOWN_BAD_MATCH_KIND.PackageName]: "COMMAND_EXEC",
  [KNOWN_BAD_MATCH_KIND.UrlPattern]: "CONFIG_PRESENT",
};

function makeKnownBadFinding(
  input: KnownBadDetectionInput,
  kind: KnownBadMatchKind,
  field: string,
  description: string,
  evidence: string,
): Finding {
  return {
    rule_id: KNOWN_BAD_RULE_ID,
    finding_id: `KNOWN_MALICIOUS_CONTENT-${kind}-${input.filePath}-${field}-${evidence}`,
    severity: "CRITICAL",
    category: MATCH_KIND_CATEGORY[kind],
    layer: "L2",
    file_path: input.filePath,
    location: { field },
    description,
    affected_tools: ["claude-code", "codex-cli", "opencode", "cursor", "windsurf"],
    cve: null,
    owasp: ["ASI05"],
    cwe: "CWE-506",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["quarantine_file", "remove_field"],
    metadata: {
      sources: [input.filePath, field],
      risk_tags: ["known-bad", kind],
      origin: "known-bad",
    },
    evidence,
    suppressed: false,
  };
}

function detectFileHashMatch(input: KnownBadDetectionInput): Finding[] {
  const hash = createHash("sha256").update(input.textContent, "utf8").digest("hex");
  if (!input.indicators.fileSha256.has(hash)) {
    return [];
  }
  return [
    makeKnownBadFinding(
      input,
      KNOWN_BAD_MATCH_KIND.FileHash,
      "content",
      `File content matches a known-malicious SHA-256 indicator (${hash}). ` +
        "Quarantine this file and audit how it got here.",
      `sha256:${hash}`,
    ),
  ];
}

function detectPackageNameMatches(input: KnownBadDetectionInput): Finding[] {
  const findings: Finding[] = [];
  for (const launch of collectMcpPackageLaunches(input.parsed)) {
    const { name } = parsePackageLocator(launch.registry, launch.locator);
    if (!input.indicators.packageNames.has(name.toLowerCase())) {
      continue;
    }
    findings.push(
      makeKnownBadFinding(
        input,
        KNOWN_BAD_MATCH_KIND.PackageName,
        launch.serverPath,
        `MCP server runs ${launch.registry} package "${name}", which is a known-malicious package. ` +
          "Remove this server configuration immediately.",
        `${launch.serverPath}: ${launch.locator}`,
      ),
    );
  }
  return findings;
}

function detectUrlPatternMatches(input: KnownBadDetectionInput): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<string>();
  for (const match of input.textContent.matchAll(URL_PATTERN)) {
    const url = match[0];
    const normalized = url.toLowerCase();
    const pattern = input.indicators.urlPatterns.find((entry) => normalized.includes(entry));
    if (!pattern || reported.has(normalized)) {
      continue;
    }
    reported.add(normalized);
    findings.push(
      makeKnownBadFinding(
        input,
        KNOWN_BAD_MATCH_KIND.UrlPattern,
        "content",
        `File references "${url}", which matches the known-malicious URL indicator "${pattern}". ` +
          "Remove the reference and audit anything fetched from it.",
        url,
      ),
    );
  }
  return findings;
}

export function detectKnownBadContent(input: KnownBadDetectionInput): Finding[] {
  if (!hasKnownBadIndicators(input.indicators)) {
    return [];
  }
  return [
    ...detectFileHashMatch(input),
    ...detectPackageNameMatches(input),
    ...detectUrlPatternMatches(input),
  ];
}

/**
 * Escalate findings whose stable fingerprint appears in the known-bad
 * indicator set to CRITICAL. Runs on the assembled finding list so it also
 * covers findings produced outside the static engine.
 */
export function escalateKnownBadFindings(
  findings: Finding[],
  indicators: ResolvedKnownBadIndicators,
): Finding[] {
  if (indicators.findingFingerprints.size === 0) {
    return findings;
  }
  return findings.map((finding) => {
    const fingerprint = finding.fingerprint ?? buildFindingFingerprint(finding);
    if (!indicators.findingFingerprints.has(fingerprint)) {
      return finding;
    }
    return {
      ...finding,
      severity: "CRITICAL",
      description:
        `${finding.description} This finding matches a known-malicious indicator ` +
        "and has been escalated to CRITICAL.",
      metadata: {
        ...finding.metadata,
        risk_tags: [...(finding.metadata?.risk_tags ?? []), "known-bad"],
      },
    };
  });
}
