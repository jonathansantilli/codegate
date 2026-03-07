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
const EXCERPT_SIGNAL_PATTERN =
  /\b(?:allowed-tools|ignore previous instructions|secret instructions|curl\b|wget\b|bash\b|sh\b|powershell\b|cookies?\s+(?:export|import|get)|session\s+share|profile\s+sync|real chrome|login sessions|session tokens?|tunnel\b|trycloudflare|webhook|upload externally|install\s+-g|@latest|bootstrap\b|restart\b|mcp configuration)\b|\.claude\/(?:hooks|settings\.json|agents\/)|\bclaude\.md\b/iu;

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
  return candidates
    .filter(isLocalTextCandidate)
    .map((candidate) => ({
      id: `local:${candidate.reportPath}`,
      reportPath: candidate.reportPath,
      absolutePath: candidate.absolutePath,
      textContent: candidate.textContent,
      referencedUrls: extractReferencedUrls(candidate.textContent),
    }));
}

export function supportsToollessLocalTextAnalysis(tool: MetaAgentTool): boolean {
  return tool === "claude";
}

export function buildPromptEvidenceText(textContent: string): string {
  const lines = textContent.split(/\r?\n/u);
  const excerptLineNumbers = new Set<number>();

  for (let index = 0; index < Math.min(lines.length, 8); index += 1) {
    excerptLineNumbers.add(index + 1);
  }

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (!EXCERPT_SIGNAL_PATTERN.test(line)) {
      continue;
    }

    excerptLineNumbers.add(index + 1);
  }

  const selected = Array.from(excerptLineNumbers)
    .sort((left, right) => left - right)
    .slice(0, 80);

  const excerptBlocks = selected.map((lineNumber) => `${lineNumber} | ${lines[lineNumber - 1] ?? ""}`);
  return [
    "File stats:",
    `- total lines: ${lines.length}`,
    `- total chars: ${textContent.length}`,
    "Key excerpts:",
    ...excerptBlocks,
  ].join("\n");
}
