import { detectCommandExecution } from "./detectors/command-exec.js";
import { detectConsentBypass } from "./detectors/consent-bypass.js";
import { detectEnvOverrides } from "./detectors/env-override.js";
import { detectGitHookIssues, type GitHookEntry } from "./detectors/git-hooks.js";
import { detectIdeSettingsIssues } from "./detectors/ide-settings.js";
import { detectPluginManifestIssues } from "./detectors/plugin-manifest.js";
import { detectRuleFileIssues } from "./detectors/rule-file.js";
import { detectSymlinkEscapes, type SymlinkEscapeEntry } from "./detectors/symlink.js";
import type { Finding } from "../types/finding.js";
import type { DiscoveryFormat } from "../types/discovery.js";

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
}

export interface StaticEngineInput {
  projectRoot: string;
  files: StaticFileInput[];
  symlinkEscapes: SymlinkEscapeEntry[];
  hooks: GitHookEntry[];
  config: StaticEngineConfig;
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

    if (file.format === "text" || file.format === "markdown") {
      findings.push(
        ...detectRuleFileIssues({
          filePath: file.filePath,
          textContent: file.textContent,
          unicodeAnalysis: input.config.unicodeAnalysis,
        }),
      );
    }
  }

  findings.push(...detectSymlinkEscapes({ symlinkEscapes: input.symlinkEscapes }));
  findings.push(...detectGitHookIssues({ hooks: input.hooks, knownSafeHooks: input.config.knownSafeHooks }));

  return dedupeFindings(findings);
}
