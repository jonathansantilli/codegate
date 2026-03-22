import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";

export interface AdvisoryIntelligenceInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

interface AdvisoryMetadata {
  sources?: string[];
  sinks?: string[];
  referenced_secrets?: string[];
  risk_tags?: string[];
  origin?: string;
}

interface AdvisoryComponent {
  id: string;
  rule_id: string;
  severity: Finding["severity"];
  category: Finding["category"];
  description: string;
  signatures: string[];
  file_patterns: string[];
  remediation_actions: string[];
  metadata?: AdvisoryMetadata;
  owasp: string[];
  cwe: string;
  confidence: Finding["confidence"];
}

interface StringCandidate {
  path: string;
  value: string;
}

const COMPONENTS_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "../advisories/agent-components.json",
);

const GENERIC_AFFECTED_TOOLS = [
  "claude-code",
  "codex-cli",
  "opencode",
  "cursor",
  "windsurf",
  "github-copilot",
];

function globToRegExp(glob: string): RegExp {
  const pattern = glob.replaceAll("\\", "/").trim();
  if (pattern.length === 0) {
    return /^$/u;
  }

  let regex = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];

    if (char === "*") {
      if (pattern[index + 1] === "*") {
        regex += ".*";
        index += 1;
      } else {
        regex += "[^/]*";
      }
      continue;
    }

    if (char === "?") {
      regex += "[^/]";
      continue;
    }

    if ("\\^$.*+?()[]{}|".includes(char)) {
      regex += `\\${char}`;
      continue;
    }

    regex += char;
  }

  regex += "$";
  return new RegExp(regex, "u");
}

function matchesGlob(value: string, glob: string): boolean {
  const normalizedValue = value.replaceAll("\\", "/");
  const normalizedGlob = glob.replaceAll("\\", "/").trim();

  if (normalizedGlob.startsWith("**/")) {
    const suffix = normalizedGlob.slice(3);
    return normalizedValue === suffix || normalizedValue.endsWith(`/${suffix}`);
  }

  return globToRegExp(normalizedGlob).test(normalizedValue);
}

function loadComponents(): AdvisoryComponent[] {
  const raw = readFileSync(COMPONENTS_PATH, "utf8");
  const parsed = JSON.parse(raw) as AdvisoryComponent[];
  return parsed;
}

const ADVISORY_COMPONENTS = loadComponents();

function normalizeToken(value: string): string {
  return value.trim().toLowerCase();
}

function collectStringCandidates(
  value: unknown,
  path: string[] = [],
  output: StringCandidate[] = [],
): StringCandidate[] {
  if (typeof value === "string") {
    output.push({ path: path.join("."), value });
    return output;
  }

  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      collectStringCandidates(entry, [...path, String(index)], output);
    });
    return output;
  }

  if (!value || typeof value !== "object") {
    return output;
  }

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    collectStringCandidates(child, [...path, key], output);
  }

  return output;
}

function makeFinding(
  filePath: string,
  matchedPath: string,
  component: AdvisoryComponent,
  signature: string,
  evidence?: FindingEvidence | null,
): Finding {
  const location: Finding["location"] = { field: matchedPath };
  if (typeof evidence?.line === "number") {
    location.line = evidence.line;
  }
  if (typeof evidence?.column === "number") {
    location.column = evidence.column;
  }

  return {
    rule_id: component.rule_id,
    finding_id: `${component.rule_id}-${filePath}-${matchedPath}`,
    severity: component.severity,
    category: component.category,
    layer: "L2",
    file_path: filePath,
    location,
    description: component.description,
    affected_tools: GENERIC_AFFECTED_TOOLS,
    cve: null,
    owasp: component.owasp,
    cwe: component.cwe,
    confidence: component.confidence,
    fixable: true,
    remediation_actions: component.remediation_actions,
    metadata: {
      sources: component.metadata?.sources ?? [],
      sinks: component.metadata?.sinks ?? [],
      referenced_secrets: component.metadata?.referenced_secrets ?? [],
      risk_tags: component.metadata?.risk_tags ?? [],
      origin: component.metadata?.origin ?? "agent-components.json",
    },
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

function componentMatchesFile(component: AdvisoryComponent, filePath: string): boolean {
  return component.file_patterns.some((pattern) => matchesGlob(filePath, pattern));
}

function signatureMatches(value: string, signatures: string[]): string | null {
  const normalizedValue = normalizeToken(value);
  for (const signature of signatures) {
    const normalizedSignature = normalizeToken(signature);
    if (normalizedSignature.length > 0 && normalizedValue.includes(normalizedSignature)) {
      return signature;
    }
  }
  return null;
}

function detectComponentMatch(
  input: AdvisoryIntelligenceInput,
  component: AdvisoryComponent,
): Finding | null {
  if (!componentMatchesFile(component, input.filePath)) {
    return null;
  }

  const stringCandidates = collectStringCandidates(input.parsed);
  for (const candidate of stringCandidates) {
    const signature = signatureMatches(candidate.value, component.signatures);
    if (!signature) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      jsonPaths: candidate.path.length > 0 ? [candidate.path] : [],
      searchTerms: [signature],
      fallbackValue: `${candidate.path} = ${candidate.value}`,
    });
    return makeFinding(
      input.filePath,
      candidate.path || component.id,
      component,
      signature,
      evidence,
    );
  }

  for (const signature of component.signatures) {
    if (!signatureMatches(input.textContent, [signature])) {
      continue;
    }

    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [signature],
      fallbackValue: signature,
    });
    return makeFinding(input.filePath, component.id, component, signature, evidence);
  }

  return null;
}

export function detectAdvisoryIntelligence(input: AdvisoryIntelligenceInput): Finding[] {
  const findings: Finding[] = [];

  for (const component of ADVISORY_COMPONENTS) {
    const finding = detectComponentMatch(input, component);
    if (finding) {
      findings.push(finding);
    }
  }

  return findings;
}
