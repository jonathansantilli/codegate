import { load as parseYaml } from "js-yaml";
import type { Finding } from "../../types/finding.js";
import { normalizeForMatching } from "../text/normalize.js";
import {
  REMOTE_INSTRUCTION_INDIRECTION_PATTERN,
  REMOTE_SHELL_PATTERN,
  findOverridePhrase,
} from "../text/threat-patterns.js";

export interface SkillFrontmatterInput {
  filePath: string;
  textContent: string;
}

const SKILL_FILE_NAME = "skill.md";
const FRONTMATTER_PATTERN = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u;

// Tool grants that hand a skill unrestricted execution or wildcard access.
const BROAD_TOOL_BASES = new Set(["bash", "shell", "terminal", "exec", "execute"]);
const WILDCARD_GRANTS = new Set(["*", "all"]);

function isSkillFile(filePath: string): boolean {
  const segments = filePath.replaceAll("\\", "/").split("/");
  return (segments[segments.length - 1] ?? "").toLowerCase() === SKILL_FILE_NAME;
}

function skillDirectoryName(filePath: string): string | null {
  const segments = filePath.replaceAll("\\", "/").split("/");
  return segments.length >= 2 ? (segments[segments.length - 2] ?? null) : null;
}

function makeFinding(
  input: SkillFrontmatterInput,
  ruleId: string,
  field: string,
  severity: Finding["severity"],
  category: Finding["category"],
  description: string,
  cwe: string,
): Finding {
  return {
    rule_id: ruleId,
    finding_id: `SKILL_FRONTMATTER-${input.filePath}-${field}`,
    severity,
    category,
    layer: "L2",
    file_path: input.filePath,
    location: { field: `frontmatter.${field}` },
    description,
    affected_tools: ["claude-code", "codex-cli", "opencode", "cursor"],
    cve: null,
    owasp: ["ASI02"],
    cwe,
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field", "quarantine_file"],
    metadata: {
      sources: [input.filePath, field],
      risk_tags: ["skill", "frontmatter"],
      origin: "skill-frontmatter",
    },
    suppressed: false,
  };
}

function parseFrontmatter(textContent: string): Record<string, unknown> | null {
  const match = textContent.match(FRONTMATTER_PATTERN);
  if (!match?.[1]) {
    return null;
  }
  try {
    const parsed = parseYaml(match[1]) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function collectToolGrants(value: unknown): string[] {
  if (typeof value === "string") {
    return value
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  }
  if (Array.isArray(value)) {
    return value
      .filter((entry): entry is string => typeof entry === "string")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  }
  return [];
}

interface ParsedToolGrant {
  raw: string;
  base: string;
  qualifier: string | null;
}

function parseToolGrant(raw: string): ParsedToolGrant {
  const match = raw.match(/^([^()]+)(?:\(([^)]*)\))?$/u);
  const base = (match?.[1] ?? raw).trim().toLowerCase();
  const qualifier = match?.[2] !== undefined ? match[2].trim() : null;
  return { raw, base, qualifier };
}

function isBroadGrant(grant: ParsedToolGrant): boolean {
  if (WILDCARD_GRANTS.has(grant.base)) {
    return true;
  }
  if (!BROAD_TOOL_BASES.has(grant.base)) {
    return false;
  }
  return grant.qualifier === null || grant.qualifier === "" || grant.qualifier === "*";
}

function frontmatterTextFields(frontmatter: Record<string, unknown>): string[] {
  const texts: string[] = [];
  for (const value of Object.values(frontmatter)) {
    if (typeof value === "string") {
      texts.push(value);
    }
  }
  return texts;
}

export function detectSkillFrontmatterIssues(input: SkillFrontmatterInput): Finding[] {
  if (!isSkillFile(input.filePath)) {
    return [];
  }

  const frontmatter = parseFrontmatter(input.textContent);
  if (!frontmatter) {
    return [];
  }

  const findings: Finding[] = [];

  const grantsRaw = frontmatter["allowed-tools"] ?? frontmatter.allowed_tools;
  const broadGrants = collectToolGrants(grantsRaw).map(parseToolGrant).filter(isBroadGrant);
  if (broadGrants.length > 0) {
    findings.push(
      makeFinding(
        input,
        "skill-allowed-tools-broad",
        "allowed-tools",
        "HIGH",
        "CONSENT_BYPASS",
        `Skill frontmatter requests unrestricted tool access: ${broadGrants
          .map((grant) => grant.raw)
          .join(", ")}. Unqualified shell or wildcard grants let the skill run arbitrary commands.`,
        "CWE-250",
      ),
    );
  }

  const hiddenInstructionTexts = frontmatterTextFields(frontmatter).filter((text) => {
    const normalized = normalizeForMatching(text);
    return (
      findOverridePhrase(normalized) !== null ||
      REMOTE_SHELL_PATTERN.test(normalized) ||
      REMOTE_INSTRUCTION_INDIRECTION_PATTERN.test(normalized)
    );
  });
  if (hiddenInstructionTexts.length > 0) {
    findings.push(
      makeFinding(
        input,
        "skill-frontmatter-hidden-instructions",
        "metadata",
        "HIGH",
        "RULE_INJECTION",
        "Skill frontmatter metadata contains override, remote-shell, or remote-instruction language " +
          "outside the visible skill body.",
        "CWE-116",
      ),
    );
  }

  const declaredName = typeof frontmatter.name === "string" ? frontmatter.name.trim() : null;
  const directoryName = skillDirectoryName(input.filePath);
  if (declaredName && directoryName && declaredName.toLowerCase() !== directoryName.toLowerCase()) {
    findings.push(
      makeFinding(
        input,
        "skill-frontmatter-mismatch",
        "name",
        "INFO",
        "CONFIG_PRESENT",
        `Skill frontmatter name "${declaredName}" does not match its directory "${directoryName}". ` +
          "Name confusion is a common registry-squatting signal.",
        "CWE-1021",
      ),
    );
  }

  return findings;
}
