import type { Finding } from "../types/finding.js";
import { scanEncodedPayloads } from "../layer2-static/text/encoded-payloads.js";
import { normalizeForMatching } from "../layer2-static/text/normalize.js";
import {
  COMMAND_EXECUTION_PATTERN,
  EXFIL_PATTERN,
  SENSITIVE_FILE_PATTERN,
  findOverridePhrase,
} from "../layer2-static/text/threat-patterns.js";
import { HIDDEN_UNICODE_CLASS, findHiddenUnicode } from "../layer2-static/text/unicode.js";

export interface ToolDescription {
  name: string;
  description: string;
}

export interface ToolDescriptionScannerInput {
  serverId: string;
  tools: ToolDescription[];
  unicodeAnalysis?: boolean;
}

function makeFinding(
  input: ToolDescriptionScannerInput,
  tool: ToolDescription,
  ruleId: string,
  severity: Finding["severity"],
  description: string,
): Finding {
  return {
    rule_id: ruleId,
    finding_id: `TOOL_DESC-${input.serverId}-${tool.name}-${ruleId}`,
    severity,
    category: "RULE_INJECTION",
    layer: "L3",
    file_path: input.serverId,
    location: { field: `tools.${tool.name}.description` },
    description,
    affected_tools: [],
    cve: null,
    owasp: ["ASI02", "ASI08"],
    cwe: "CWE-20",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    suppressed: false,
  };
}

export function scanToolDescriptions(input: ToolDescriptionScannerInput): Finding[] {
  const findings: Finding[] = [];

  for (const tool of input.tools) {
    const text = tool.description;
    const normalized = normalizeForMatching(text);
    const hasSensitive = SENSITIVE_FILE_PATTERN.test(normalized);
    const hasExfil = EXFIL_PATTERN.test(normalized);
    const overrideMatch = findOverridePhrase(normalized);
    const hasExec = COMMAND_EXECUTION_PATTERN.test(normalized);
    const hiddenMatches = input.unicodeAnalysis === false ? [] : findHiddenUnicode(text);
    const tagMatches = hiddenMatches.filter((match) => match.class === HIDDEN_UNICODE_CLASS.Tags);
    const otherHiddenMatches = hiddenMatches.filter(
      (match) => match.class !== HIDDEN_UNICODE_CLASS.Tags,
    );
    const isLong = text.length > 1000;

    if (hasSensitive && hasExfil) {
      findings.push(
        makeFinding(
          input,
          tool,
          "tool-description-sensitive-exfiltration",
          "CRITICAL",
          `Tool description references sensitive file access with exfiltration behavior: ${tool.name}`,
        ),
      );
    }

    if (overrideMatch) {
      findings.push(
        makeFinding(
          input,
          tool,
          "tool-description-instruction-override",
          "HIGH",
          `Tool description contains instruction-override language ("${overrideMatch.phrase}"): ${tool.name}`,
        ),
      );
    }

    if (hasExec) {
      findings.push(
        makeFinding(
          input,
          tool,
          "tool-description-command-execution",
          "HIGH",
          `Tool description encourages command execution patterns: ${tool.name}`,
        ),
      );
    }

    if (otherHiddenMatches.length > 0) {
      findings.push(
        makeFinding(
          input,
          tool,
          "tool-description-hidden-unicode",
          "MEDIUM",
          `Tool description includes hidden Unicode characters: ${tool.name}`,
        ),
      );
    }

    if (tagMatches.length > 0) {
      findings.push(
        makeFinding(
          input,
          tool,
          "tool-description-hidden-unicode-tags",
          "HIGH",
          `Tool description includes ${tagMatches.length} Unicode tag character(s) ` +
            `(U+E0000-U+E007F, ASCII smuggling): ${tool.name}`,
        ),
      );
    }

    for (const payload of scanEncodedPayloads(text)) {
      findings.push(
        makeFinding(
          input,
          tool,
          "tool-description-encoded-payload",
          payload.matchesRemoteShell ? "CRITICAL" : "HIGH",
          `Tool description contains a ${payload.kind}-encoded payload with hidden instructions: ${tool.name}`,
        ),
      );
    }

    if (isLong) {
      findings.push(
        makeFinding(
          input,
          tool,
          "tool-description-unusually-long",
          "MEDIUM",
          `Tool description is unusually long and may hide instructions: ${tool.name}`,
        ),
      );
    }
  }

  return findings;
}
