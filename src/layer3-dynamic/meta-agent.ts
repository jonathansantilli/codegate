import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const templatesRoot = join(dirname(fileURLToPath(import.meta.url)), "prompt-templates");

export interface SecurityAnalysisPromptInput {
  resourceId: string;
  resourceSummary: string;
}

export interface LocalTextAnalysisPromptInput {
  filePaths: string[];
  referencedUrls?: string[];
}

export interface ToolPoisoningPromptInput {
  resourceId: string;
  toolName: string;
  evidence: string;
}

function readTemplate(name: string): string {
  return readFileSync(join(templatesRoot, name), "utf8");
}

function normalize(value: string): string {
  return value.replace(/[\u200B-\u200D\u2060\uFEFF]/gu, "").trim();
}

export function buildSecurityAnalysisPrompt(input: SecurityAnalysisPromptInput): string {
  return readTemplate("security-analysis.md")
    .replaceAll("{{RESOURCE_ID}}", normalize(input.resourceId))
    .replaceAll("{{RESOURCE_SUMMARY}}", normalize(input.resourceSummary));
}

export function buildLocalTextAnalysisPrompt(input: LocalTextAnalysisPromptInput): string {
  const referencedUrls =
    input.referencedUrls && input.referencedUrls.length > 0
      ? input.referencedUrls.map((url) => `- ${normalize(url)}`).join("\n")
      : "- none";
  const filePaths = input.filePaths.map((fp) => `- ${normalize(fp)}`).join("\n");

  return readTemplate("local-text-analysis.md")
    .replaceAll("{{FILE_PATHS}}", filePaths)
    .replaceAll("{{REFERENCED_URLS}}", referencedUrls);
}

export function buildToolPoisoningPrompt(input: ToolPoisoningPromptInput): string {
  return readTemplate("tool-poisoning.md")
    .replaceAll("{{RESOURCE_ID}}", normalize(input.resourceId))
    .replaceAll("{{TOOL_NAME}}", normalize(input.toolName))
    .replaceAll("{{EVIDENCE}}", normalize(input.evidence));
}
