import type { DiscoveryFormat } from "../types/discovery.js";
import type { MetaAgentTool } from "./command-builder.js";

export interface LocalTextAnalysisCandidate {
  reportPath: string;
  absolutePath: string;
  format: DiscoveryFormat;
  textContent: string;
}

export interface LocalTextAnalysisTarget {
  id: string;
  reportPath: string;
  absolutePath: string;
  textContent: string;
  referencedUrls: string[];
}

const LOCAL_TEXT_PATH_PATTERNS = [
  /^agents\.md$/iu,
  /^claude\.md$/iu,
  /^codex\.md$/iu,
  /(?:^|\/)agents\.md$/iu,
  /(?:^|\/)claude\.md$/iu,
  /(?:^|\/)codex\.md$/iu,
  /(?:^|\/)skill\.md$/iu,
  /(?:^|\/)[^/]+\.mdc$/iu,
  /^\.codex\/.*\.(?:md|mdc)$/iu,
  /^\.cursor\/rules\/.*\.mdc$/iu,
  /^\.opencode\/(?:rules|skills|commands)\/.*\.md$/iu,
  /^\.roo\/(?:rules|skills|commands)\/.*\.md$/iu,
  /^\.kiro\/(?:steering|commands)\/.*\.(?:md|txt)$/iu,
  /^\.windsurf.*\.md$/iu,
  /^\.github\/copilot-instructions\.md$/iu,
];

function normalizeReportPath(reportPath: string): string {
  return reportPath.replaceAll("\\", "/");
}

function isLocalTextCandidate(candidate: LocalTextAnalysisCandidate): boolean {
  if (candidate.format !== "markdown" && candidate.format !== "text") {
    return false;
  }

  const normalized = normalizeReportPath(candidate.reportPath);
  return LOCAL_TEXT_PATH_PATTERNS.some((pattern) => pattern.test(normalized));
}

export function extractReferencedUrls(textContent: string): string[] {
  const matches = textContent.match(/https?:\/\/[^\s<>"'`)\]]+/giu) ?? [];
  const unique = new Set<string>();
  for (const match of matches) {
    unique.add(match);
  }
  return Array.from(unique);
}

export function collectLocalTextAnalysisTargets(
  candidates: LocalTextAnalysisCandidate[],
): LocalTextAnalysisTarget[] {
  return candidates.filter(isLocalTextCandidate).map((candidate) => ({
    id: `local:${candidate.reportPath}`,
    reportPath: candidate.reportPath,
    absolutePath: candidate.absolutePath,
    textContent: candidate.textContent,
    referencedUrls: extractReferencedUrls(candidate.textContent),
  }));
}

export function supportsAgentLocalTextAnalysis(tool: MetaAgentTool): boolean {
  return tool === "claude" || tool === "codex";
}

/**
 * @deprecated Use supportsAgentLocalTextAnalysis instead. Kept for backward compatibility.
 */
export function supportsToollessLocalTextAnalysis(tool: MetaAgentTool): boolean {
  return supportsAgentLocalTextAnalysis(tool);
}
