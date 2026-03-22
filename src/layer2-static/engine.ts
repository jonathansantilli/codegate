import { detectCommandExecution } from "./detectors/command-exec.js";
import { detectAdvisoryIntelligence } from "./detectors/advisory-intelligence.js";
import { detectConsentBypass } from "./detectors/consent-bypass.js";
import { detectEnvOverrides } from "./detectors/env-override.js";
import { detectGitHookIssues, type GitHookEntry } from "./detectors/git-hooks.js";
import { detectIdeSettingsIssues } from "./detectors/ide-settings.js";
import { detectPluginManifestIssues } from "./detectors/plugin-manifest.js";
import { detectRuleFileIssues } from "./detectors/rule-file.js";
import { detectSymlinkEscapes, type SymlinkEscapeEntry } from "./detectors/symlink.js";
import { FINDING_CATEGORIES, type Finding } from "../types/finding.js";
import type { DiscoveryFormat } from "../types/discovery.js";
import { buildFindingEvidence } from "./evidence.js";
import { evaluateRule, loadRulePacks, type DetectionRule } from "./rule-engine.js";

export interface StaticFileInput {
  filePath: string;
  format: DiscoveryFormat;
  parsed: unknown;
  textContent: string;
}

export interface StaticEngineConfig {
  knownSafeMcpServers: string[];
  knownSafeFormatters: string[];
  knownSafeLspServers: string[];
  knownSafeHooks: string[];
  blockedCommands: string[];
  trustedApiDomains: string[];
  unicodeAnalysis: boolean;
  checkIdeSettings: boolean;
  rulePackPaths?: string[];
  allowedRules?: string[];
  skipRules?: string[];
}

export interface StaticEngineInput {
  projectRoot: string;
  files: StaticFileInput[];
  symlinkEscapes: SymlinkEscapeEntry[];
  hooks: GitHookEntry[];
  config: StaticEngineConfig;
}

const GENERIC_AFFECTED_TOOLS = [
  "claude-code",
  "codex-cli",
  "opencode",
  "cursor",
  "windsurf",
  "github-copilot",
];

function parseRuleSeverity(value: string): Finding["severity"] {
  const normalized = value.trim().toUpperCase();
  if (
    normalized === "CRITICAL" ||
    normalized === "HIGH" ||
    normalized === "MEDIUM" ||
    normalized === "LOW"
  ) {
    return normalized;
  }
  return "INFO";
}

function parseRuleCategory(value: string): Finding["category"] {
  const normalized = value.trim().toUpperCase();
  if (FINDING_CATEGORIES.some((category) => category === normalized)) {
    return normalized as Finding["category"];
  }
  return "CONFIG_PRESENT";
}

function remediationActionsForRule(rule: DetectionRule): string[] {
  if (rule.query_type === "text_pattern") {
    return ["quarantine_file", "remove_block"];
  }
  return ["remove_field", "replace_with_default"];
}

function findingFromRulePackMatch(file: StaticFileInput, rule: DetectionRule): Finding {
  const locationField = rule.query_type === "text_pattern" ? "content" : rule.query;
  const evidence = buildFindingEvidence({
    textContent: file.textContent,
    searchTerms: [rule.query],
    fallbackValue: `${locationField} matched rule ${rule.id}`,
  });
  const affectedTools = rule.tool === "*" ? GENERIC_AFFECTED_TOOLS : [rule.tool];

  return {
    rule_id: rule.id,
    finding_id: `RULE_PACK-${rule.id}-${file.filePath}-${locationField}`,
    severity: parseRuleSeverity(rule.severity),
    category: parseRuleCategory(rule.category),
    layer: "L2",
    file_path: file.filePath,
    location: { field: locationField },
    description: rule.description,
    affected_tools: affectedTools,
    cve: rule.cve ?? null,
    owasp: rule.owasp,
    cwe: rule.cwe,
    confidence: "HIGH",
    fixable: true,
    remediation_actions: remediationActionsForRule(rule),
    metadata: {
      sources: [file.filePath, locationField],
      risk_tags: ["rule-pack"],
      origin: "rule-pack",
    },
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

function hasEquivalentFinding(findings: Finding[], candidate: Finding): boolean {
  return findings.some(
    (finding) =>
      finding.rule_id === candidate.rule_id &&
      finding.file_path === candidate.file_path &&
      (finding.location.field ?? "") === (candidate.location.field ?? ""),
  );
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const deduped = new Map<string, Finding>();

  for (const finding of findings) {
    const key = `${finding.category}:${finding.rule_id}:${finding.description}`;
    const existing = deduped.get(key);

    if (!existing) {
      deduped.set(key, {
        ...finding,
        affected_locations: [{ file_path: finding.file_path, location: finding.location }],
      });
      continue;
    }

    const nextLocation = { file_path: finding.file_path, location: finding.location };
    const locations = existing.affected_locations ?? [];
    const alreadyIncluded = locations.some(
      (location) =>
        location.file_path === nextLocation.file_path &&
        location.location?.field === nextLocation.location?.field &&
        location.location?.line === nextLocation.location?.line,
    );
    if (!alreadyIncluded) {
      locations.push(nextLocation);
    }
    existing.affected_locations = locations;
  }

  return Array.from(deduped.values());
}

export function runStaticEngine(input: StaticEngineInput): Finding[] {
  const findings: Finding[] = [];
  const rulePackRules = loadRulePacks({
    rule_pack_paths: input.config.rulePackPaths ?? [],
    allowed_rules: input.config.allowedRules ?? [],
    skip_rules: input.config.skipRules ?? [],
  });

  for (const file of input.files) {
    findings.push(
      ...detectEnvOverrides({
        filePath: file.filePath,
        parsed: file.parsed,
        textContent: file.textContent,
        trustedApiDomains: input.config.trustedApiDomains,
      }),
    );

    findings.push(
      ...detectConsentBypass({
        filePath: file.filePath,
        parsed: file.parsed,
        textContent: file.textContent,
        trustedApiDomains: input.config.trustedApiDomains,
      }),
    );

    findings.push(
      ...detectCommandExecution({
        filePath: file.filePath,
        parsed: file.parsed,
        textContent: file.textContent,
        knownSafeMcpServers: input.config.knownSafeMcpServers,
        knownSafeFormatters: input.config.knownSafeFormatters,
        knownSafeLspServers: input.config.knownSafeLspServers,
        blockedCommands: input.config.blockedCommands,
      }),
    );

    if (input.config.checkIdeSettings) {
      findings.push(
        ...detectIdeSettingsIssues({
          filePath: file.filePath,
          parsed: file.parsed,
          textContent: file.textContent,
          projectRoot: input.projectRoot,
        }),
      );
    }

    findings.push(
      ...detectPluginManifestIssues({
        filePath: file.filePath,
        parsed: file.parsed,
        textContent: file.textContent,
        trustedApiDomains: input.config.trustedApiDomains,
        blockedCommands: input.config.blockedCommands,
      }),
    );

    findings.push(
      ...detectAdvisoryIntelligence({
        filePath: file.filePath,
        parsed: file.parsed,
        textContent: file.textContent,
      }),
    );

    if (file.format === "text" || file.format === "markdown") {
      findings.push(
        ...detectRuleFileIssues({
          filePath: file.filePath,
          textContent: file.textContent,
          unicodeAnalysis: input.config.unicodeAnalysis,
        }),
      );
    }

    for (const rule of rulePackRules) {
      if (
        !evaluateRule(rule, {
          filePath: file.filePath,
          format: file.format,
          parsed: file.parsed,
          textContent: file.textContent,
        })
      ) {
        continue;
      }

      const candidate = findingFromRulePackMatch(file, rule);
      if (!hasEquivalentFinding(findings, candidate)) {
        findings.push(candidate);
      }
    }
  }

  findings.push(...detectSymlinkEscapes({ symlinkEscapes: input.symlinkEscapes }));
  findings.push(
    ...detectGitHookIssues({ hooks: input.hooks, knownSafeHooks: input.config.knownSafeHooks }),
  );

  return dedupeFindings(findings);
}
