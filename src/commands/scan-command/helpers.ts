import { resolve } from "node:path";
import type { OutputFormat } from "../../config.js";
import type { RemediationRunnerResult } from "../../layer4-remediation/remediation-runner.js";
import { renderHtmlReport } from "../../reporter/html.js";
import { renderJsonReport } from "../../reporter/json.js";
import { renderMarkdownReport } from "../../reporter/markdown.js";
import { renderSarifReport } from "../../reporter/sarif.js";
import { renderTerminalReport } from "../../reporter/terminal.js";
import type { CodeGateReport } from "../../types/report.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function metadataSummary(metadata: unknown): string {
  let raw: string;
  if (typeof metadata === "string") {
    raw = metadata;
  } else {
    try {
      raw = JSON.stringify(metadata, null, 2);
    } catch {
      raw = String(metadata);
    }
  }

  const maxLength = 5000;
  if (raw.length <= maxLength) {
    return raw;
  }
  return `${raw.slice(0, maxLength)}\n...[truncated ${raw.length - maxLength} chars]`;
}

function parseJsonCandidate(value: string): unknown {
  return JSON.parse(value) as unknown;
}

function unwrapMetaAgentEnvelope(parsed: unknown): unknown {
  if (!isRecord(parsed)) {
    return parsed;
  }

  const result = parsed.result;
  if (typeof result !== "string") {
    return parsed;
  }

  const nested = parseMetaAgentOutput(result);
  return nested ?? parsed;
}

export function parseMetaAgentOutput(stdout: string): unknown | null {
  const trimmed = stdout.trim();
  if (trimmed.length === 0) {
    return null;
  }

  try {
    return unwrapMetaAgentEnvelope(parseJsonCandidate(trimmed));
  } catch {
    // Fall back to extracting a JSON block from markdown or mixed CLI output.
  }

  const fenced = /```(?:json)?\s*([\s\S]*?)```/giu;
  let match = fenced.exec(trimmed);
  while (match) {
    try {
      return parseJsonCandidate(match[1] ?? "");
    } catch {
      // Continue parsing additional fenced blocks.
    }
    match = fenced.exec(trimmed);
  }

  const candidates = [
    trimmed.match(/\{[\s\S]*\}/u)?.[0],
    trimmed.match(/\[[\s\S]*\]/u)?.[0],
  ];
  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    try {
      return unwrapMetaAgentEnvelope(parseJsonCandidate(candidate));
    } catch {
      // Continue trying fallback candidates.
    }
  }

  return null;
}

export function withMetaAgentFinding(
  metadata: unknown,
  finding: {
    id: string;
    severity: "INFO" | "LOW";
    description: string;
    evidence?: string;
  },
): unknown {
  const findingPayload = {
    id: finding.id,
    severity: finding.severity,
    category: "PARSE_ERROR",
    description: finding.description,
    field: "layer3.meta_agent",
    confidence: "HIGH",
    evidence: finding.evidence,
  };

  if (!isRecord(metadata)) {
    return { findings: [findingPayload] };
  }

  const existing = Array.isArray(metadata.findings) ? metadata.findings : [];
  return {
    ...metadata,
    findings: [...existing, findingPayload],
  };
}

export function mergeMetaAgentMetadata(baseMetadata: unknown, agentMetadata: unknown): unknown {
  if (!isRecord(baseMetadata)) {
    return agentMetadata;
  }
  if (!isRecord(agentMetadata)) {
    return baseMetadata;
  }

  const baseFindings = Array.isArray(baseMetadata.findings) ? baseMetadata.findings : [];
  const agentFindings = Array.isArray(agentMetadata.findings) ? agentMetadata.findings : [];

  return {
    ...baseMetadata,
    ...agentMetadata,
    findings: [...baseFindings, ...agentFindings],
  };
}

export function noEligibleDeepResourceNotes(): string[] {
  return [
    "Deep scan skipped: no eligible external resources were discovered.",
    "Deep scan analyzes only remote MCP URLs (http/sse) and package-backed commands (npx/uvx/pipx).",
    "Local stdio commands (for example `bash`) are still detected by Layer 2 but are never executed by deep scan.",
  ];
}

export function parseLocalTextFindings(filePath: string, metadata: unknown): CodeGateReport["findings"] {
  if (!isRecord(metadata) || !Array.isArray(metadata.findings)) {
    return [];
  }

  return metadata.findings
    .filter((item): item is Record<string, unknown> => isRecord(item))
    .map((item, index) => ({
      rule_id: typeof item.id === "string" ? item.id : "layer3-local-text-analysis-finding",
      finding_id: typeof item.id === "string" ? item.id : `L3-local-${filePath}-${index}`,
      severity:
        item.severity === "CRITICAL" ||
        item.severity === "HIGH" ||
        item.severity === "MEDIUM" ||
        item.severity === "LOW"
          ? item.severity
          : "INFO",
      category:
        item.category === "ENV_OVERRIDE" ||
        item.category === "COMMAND_EXEC" ||
        item.category === "CONSENT_BYPASS" ||
        item.category === "RULE_INJECTION" ||
        item.category === "IDE_SETTINGS" ||
        item.category === "SYMLINK_ESCAPE" ||
        item.category === "GIT_HOOK" ||
        item.category === "CONFIG_PRESENT" ||
        item.category === "CONFIG_CHANGE" ||
        item.category === "NEW_SERVER" ||
        item.category === "TOXIC_FLOW"
          ? item.category
          : "PARSE_ERROR",
      layer: "L3" as const,
      file_path: typeof item.file_path === "string" ? item.file_path : filePath,
      location: { field: typeof item.field === "string" ? item.field : "content" },
      description: typeof item.description === "string" ? item.description : "Local text analysis finding",
      affected_tools: [],
      cve: null,
      owasp: Array.isArray(item.owasp) ? item.owasp.filter((value): value is string => typeof value === "string") : [],
      cwe: typeof item.cwe === "string" ? item.cwe : "CWE-20",
      confidence:
        item.confidence === "HIGH" || item.confidence === "MEDIUM" ? item.confidence : "LOW",
      evidence: typeof item.evidence === "string" ? item.evidence : null,
      fixable: false,
      remediation_actions: [],
      suppressed: false,
    }));
}

function remediationModeLabel(options: {
  fixSafe?: boolean;
  remediate?: boolean;
  dryRun?: boolean;
  patch?: boolean;
}): string {
  if (options.fixSafe) {
    return "fix-safe";
  }
  if (options.remediate && options.dryRun) {
    return "remediate (dry-run)";
  }
  if (options.remediate) {
    return "remediate";
  }
  if (options.patch && options.dryRun) {
    return "patch (dry-run)";
  }
  if (options.patch) {
    return "patch";
  }
  if (options.dryRun) {
    return "dry-run";
  }
  return "remediation";
}

export function remediationSummaryLines(input: {
  scanTarget: string;
  options: {
    fixSafe?: boolean;
    remediate?: boolean;
    dryRun?: boolean;
    patch?: boolean;
  };
  before: CodeGateReport;
  result: RemediationRunnerResult;
}): string[] {
  const planned = typeof input.result.plannedCount === "number" ? input.result.plannedCount : 0;
  const applied = typeof input.result.appliedCount === "number" ? input.result.appliedCount : 0;
  const lines: string[] = [];

  lines.push("Remediation summary:");
  lines.push(`Mode: ${remediationModeLabel(input.options)}`);
  lines.push(`Planned changes: ${planned}`);
  lines.push(`Applied changes: ${applied}`);
  lines.push(`Findings before remediation: ${input.before.summary.total}`);
  lines.push(`Findings after remediation: ${input.result.report.summary.total}`);

  if (input.options.dryRun) {
    lines.push("No files were changed (dry-run).");
  } else if (applied === 0) {
    lines.push("No files were changed.");
  }

  if (input.result.backupSessionId) {
    const backupPath = resolve(input.scanTarget, ".codegate-backup", input.result.backupSessionId);
    lines.push(`Backup session: ${backupPath}`);
    lines.push(`Undo: codegate undo ${input.scanTarget}`);
  }

  const actionLines = input.result.appliedActions ?? input.result.plannedActions ?? [];
  if (actionLines.length > 0) {
    lines.push("Remediation actions:");
    for (const action of actionLines.slice(0, 10)) {
      lines.push(`- ${action.action} -> ${resolve(input.scanTarget, action.filePath)} (${action.findingId})`);
    }
    if (actionLines.length > 10) {
      lines.push(`- ...and ${actionLines.length - 10} more`);
    }
  }

  return lines;
}

export function renderByFormat(format: OutputFormat, report: CodeGateReport, options?: { verbose?: boolean }): string {
  if (format === "json") {
    return renderJsonReport(report);
  }
  if (format === "sarif") {
    return renderSarifReport(report);
  }
  if (format === "markdown") {
    return renderMarkdownReport(report);
  }
  if (format === "html") {
    return renderHtmlReport(report);
  }
  return renderTerminalReport(report, { verbose: options?.verbose === true });
}
