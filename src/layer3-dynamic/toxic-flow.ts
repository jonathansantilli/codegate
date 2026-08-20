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
  /** Maps tool name to its origin server, for cross-server workspace analysis. */
  origins?: Record<string, string>;
  /** Only report chains spanning at least two distinct origins. */
  crossOriginOnly?: boolean;
}

const MAX_REPORTED_CHAINS = 10;

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
  if (
    /(read local file|filesystem|\.ssh|id_rsa|credential|environment variable|\.env)/u.test(text)
  ) {
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

function describeTool(input: ToxicFlowInput, toolName: string): string {
  const origin = input.origins?.[toolName];
  return origin ? `${toolName} (server: ${origin})` : toolName;
}

function makeFinding(
  input: ToxicFlowInput,
  sourceTool: string,
  sensitiveTool: string,
  sinkTool: string,
): Finding {
  return {
    rule_id: "toxic-flow-chain-detected",
    finding_id: `TOXIC_FLOW-${input.scopeId}-${sourceTool}-${sensitiveTool}-${sinkTool}`,
    severity: "CRITICAL",
    category: "TOXIC_FLOW",
    layer: "L3",
    file_path: input.scopeId,
    location: { field: "tool_interaction_graph" },
    description: `Toxic Flow detected: ${describeTool(input, sourceTool)} -> ${describeTool(
      input,
      sensitiveTool,
    )} -> ${describeTool(
      input,
      sinkTool,
    )}. This chain can propagate untrusted input into sensitive data access and external exfiltration.`,
    affected_tools: [],
    cve: null,
    owasp: ["ASI08"],
    cwe: "CWE-20",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    metadata: {
      sources: [sourceTool],
      sinks: [sinkTool],
      risk_tags: ["toxic-flow"],
      origin: "toxic-flow",
    },
    suppressed: false,
  };
}

function distinctOriginCount(input: ToxicFlowInput, toolNames: string[]): number {
  const origins = new Set<string>();
  for (const name of toolNames) {
    const origin = input.origins?.[name];
    if (origin) {
      origins.add(origin);
    }
  }
  return origins.size;
}

export function detectToxicFlows(input: ToxicFlowInput): Finding[] {
  const classified = classifyTools(input);
  const untrusted = classified
    .filter((entry) => entry.classes.has("untrusted_input"))
    .map((entry) => entry.tool.name);
  const sensitive = classified
    .filter((entry) => entry.classes.has("sensitive_access"))
    .map((entry) => entry.tool.name);
  const exfil = classified
    .filter((entry) => entry.classes.has("exfiltration_sink"))
    .map((entry) => entry.tool.name);

  const findings: Finding[] = [];
  for (const source of untrusted) {
    for (const sensitiveTool of sensitive) {
      for (const sink of exfil) {
        if (findings.length >= MAX_REPORTED_CHAINS) {
          return findings;
        }
        if (
          input.crossOriginOnly &&
          distinctOriginCount(input, [source, sensitiveTool, sink]) < 2
        ) {
          continue;
        }
        findings.push(makeFinding(input, source, sensitiveTool, sink));
      }
    }
  }

  return findings;
}
