import type { Finding } from "../types/finding.js";

export type ToxicToolClass = "untrusted_input" | "sensitive_access" | "exfiltration_sink";

export interface ToxicFlowTool {
  name: string;
  description: string;
}

export interface ToxicFlowInput {
  scopeId: string;
  tools: ToxicFlowTool[];
  knownClassifications?: Record<string, ToxicToolClass[]>;
}

interface ClassifiedTool {
  tool: ToxicFlowTool;
  classes: Set<ToxicToolClass>;
}

function classifyByDescription(description: string): Set<ToxicToolClass> {
  const classes = new Set<ToxicToolClass>();
  const text = description.toLowerCase();

  if (/(read jira|read issue|read pr|fetch web|read email|ticket content|untrusted)/u.test(text)) {
    classes.add("untrusted_input");
  }
  if (/(read local file|filesystem|\.ssh|id_rsa|credential|environment variable|\.env)/u.test(text)) {
    classes.add("sensitive_access");
  }
  if (/(send|upload|post|webhook|http request|message|external endpoint|slack)/u.test(text)) {
    classes.add("exfiltration_sink");
  }

  return classes;
}

function classifyTools(input: ToxicFlowInput): ClassifiedTool[] {
  const known = input.knownClassifications ?? {};

  return input.tools.map((tool) => {
    const classes = new Set<ToxicToolClass>();

    for (const entry of known[tool.name] ?? []) {
      classes.add(entry);
    }
    for (const entry of classifyByDescription(tool.description)) {
      classes.add(entry);
    }

    return { tool, classes };
  });
}

function makeFinding(
  input: ToxicFlowInput,
  sourceTool: string,
  sensitiveTool: string,
  sinkTool: string,
): Finding {
  return {
    rule_id: "toxic-flow-chain-detected",
    finding_id: `TOXIC_FLOW-${sourceTool}-${sensitiveTool}-${sinkTool}`,
    severity: "CRITICAL",
    category: "TOXIC_FLOW",
    layer: "L3",
    file_path: input.scopeId,
    location: { field: "tool_interaction_graph" },
    description: `Toxic Flow detected: ${sourceTool} -> ${sensitiveTool} -> ${sinkTool}. This chain can propagate untrusted input into sensitive data access and external exfiltration.`,
    affected_tools: [],
    cve: null,
    owasp: ["ASI08"],
    cwe: "CWE-20",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    suppressed: false,
  };
}

export function detectToxicFlows(input: ToxicFlowInput): Finding[] {
  const classified = classifyTools(input);
  const untrusted = classified.find((entry) => entry.classes.has("untrusted_input"))?.tool.name;
  const sensitive = classified.find((entry) => entry.classes.has("sensitive_access"))?.tool.name;
  const exfil = classified.find((entry) => entry.classes.has("exfiltration_sink"))?.tool.name;

  if (!untrusted || !sensitive || !exfil) {
    return [];
  }

  return [makeFinding(input, untrusted, sensitive, exfil)];
}
