import { isAbsolute, join, normalize, relative } from "node:path";
import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";

export interface IdeSettingsInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  projectRoot: string;
}

const KNOWN_DANGEROUS_KEYS = new Set(["php.validate.executablePath", "PATH_TO_GIT"]);

function isInsideProject(pathValue: string, projectRoot: string): boolean {
  const resolved = isAbsolute(pathValue) ? normalize(pathValue) : normalize(join(projectRoot, pathValue));
  const rel = relative(normalize(projectRoot), resolved);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function makeFinding(
  filePath: string,
  field: string,
  severity: Finding["severity"],
  ruleId: string,
  description: string,
  evidence?: FindingEvidence | null,
): Finding {
  const location: Finding["location"] = { field };
  if (typeof evidence?.line === "number") {
    location.line = evidence.line;
  }
  if (typeof evidence?.column === "number") {
    location.column = evidence.column;
  }

  return {
    rule_id: ruleId,
    finding_id: `IDE_SETTINGS-${filePath}-${field}`,
    severity,
    category: "IDE_SETTINGS",
    layer: "L2",
    file_path: filePath,
    location,
    description,
    affected_tools: ["cursor", "github-copilot", "windsurf", "claude-code"],
    cve: null,
    owasp: ["ASI05", "ASI06"],
    cwe: "CWE-78",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field", "replace_with_default"],
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

export function detectIdeSettingsIssues(input: IdeSettingsInput): Finding[] {
  if (!input.parsed || typeof input.parsed !== "object") {
    return [];
  }
  const settings = input.parsed as Record<string, unknown>;
  const findings: Finding[] = [];

  for (const [key, value] of Object.entries(settings)) {
    if (typeof value !== "string") {
      continue;
    }
    if (!isInsideProject(value, input.projectRoot)) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [`"${key}"`, key, value],
      fallbackValue: `${key} = ${value}`,
    });

    if (KNOWN_DANGEROUS_KEYS.has(key)) {
      findings.push(
        makeFinding(
          input.filePath,
          key,
          "CRITICAL",
          "ide-known-dangerous-executable-path",
          `Known-dangerous executable path key points inside project: ${key}`,
          evidence,
        ),
      );
      continue;
    }

    if (/(path|executable|binary|command|interpreter)/iu.test(key)) {
      findings.push(
        makeFinding(
          input.filePath,
          key,
          "HIGH",
          "ide-pattern-executable-path",
          `Executable-like settings key points inside project: ${key}`,
          evidence,
        ),
      );
    }
  }

  return findings;
}
