import type { Finding } from "../types/finding.js";

export interface ToolDescription {
  name: string;
  description: string;
}

export interface ToolDescriptionScannerInput {
  serverId: string;
  tools: ToolDescription[];
  unicodeAnalysis?: boolean;
}

const HIDDEN_UNICODE = /[\u200B-\u200D\u2060\uFEFF]/u;
const SENSITIVE_FILE_PATTERN = /(~\/\.ssh|~\/\.aws|id_rsa|\.env|credentials|\.git-credentials)/iu;
const EXFIL_PATTERN = /(send .*https?:\/\/|upload|webhook|post to|exfiltrat)/iu;
const OVERRIDE_PATTERN = /(ignore previous instructions|bypass safety|disable guardrails)/iu;
const EXEC_PATTERN = /(run command|execute shell|bash -c|sh -c|powershell)/iu;

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
    const hasSensitive = SENSITIVE_FILE_PATTERN.test(text);
    const hasExfil = EXFIL_PATTERN.test(text);
    const hasOverride = OVERRIDE_PATTERN.test(text);
    const hasExec = EXEC_PATTERN.test(text);
    const hasUnicode = input.unicodeAnalysis === false ? false : HIDDEN_UNICODE.test(text);
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

    if (hasOverride) {
      findings.push(
        makeFinding(
          input,
          tool,
          "tool-description-instruction-override",
          "HIGH",
          `Tool description contains instruction-override language: ${tool.name}`,
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

    if (hasUnicode) {
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
