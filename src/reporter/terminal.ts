import type { CodeGateReport } from "../types/report.js";
import type { FindingMetadata } from "../types/finding.js";
import { toAbsoluteDisplayPath } from "../path-display.js";
import { partitionRequestedTargetFindings } from "../report/requested-target-findings.js";

export interface TerminalRenderOptions {
  verbose?: boolean;
}

function appendLabeledList(lines: string[], label: string, values: string[]): void {
  if (values.length === 0) {
    return;
  }

  lines.push(`  ${label}:`);
  for (const value of values) {
    lines.push(`    - ${value}`);
  }
}

function appendLabeledText(lines: string[], label: string, value: string): void {
  if (value.length === 0) {
    return;
  }

  lines.push(`  ${label}: ${value}`);
}

function appendMetadata(lines: string[], metadata: FindingMetadata | null | undefined): void {
  if (!metadata) {
    return;
  }

  const hasContent =
    (metadata.sources?.length ?? 0) > 0 ||
    (metadata.sinks?.length ?? 0) > 0 ||
    (metadata.referenced_secrets?.length ?? 0) > 0 ||
    (metadata.risk_tags?.length ?? 0) > 0 ||
    typeof metadata.origin === "string";

  if (!hasContent) {
    return;
  }

  lines.push("  Metadata:");
  appendLabeledList(lines, "Sources", metadata.sources ?? []);
  appendLabeledList(lines, "Sinks", metadata.sinks ?? []);
  appendLabeledList(lines, "Referenced secrets", metadata.referenced_secrets ?? []);
  appendLabeledList(lines, "Risk tags", metadata.risk_tags ?? []);
  if (metadata.origin) {
    appendLabeledText(lines, "Origin", metadata.origin);
  }
}

function appendEvidence(lines: string[], evidence: string): void {
  const evidenceLines = evidence.split("\n");
  if (evidenceLines.length === 1) {
    lines.push(`  Evidence: ${evidenceLines[0]}`);
    return;
  }

  lines.push("  Evidence:");
  for (const evidenceLine of evidenceLines) {
    lines.push(`    ${evidenceLine}`);
  }
}

function formatLocation(location: {
  field?: string;
  line?: number;
  column?: number;
}): string | null {
  const parts: string[] = [];
  if (location.field) {
    parts.push(location.field);
  }
  if (typeof location.line === "number") {
    const column = typeof location.column === "number" ? `:${location.column}` : "";
    parts.push(`line ${location.line}${column}`);
  }
  return parts.length > 0 ? parts.join(" @ ") : null;
}

function appendFinding(
  lines: string[],
  report: CodeGateReport,
  options: TerminalRenderOptions,
  finding: CodeGateReport["findings"][number],
): void {
  const verbose = options.verbose === true;
  lines.push(
    `[${finding.severity}] ${toAbsoluteDisplayPath(report.scan_target, finding.file_path)}`,
  );
  lines.push(`  ${finding.description}`);
  if (finding.incident_title) {
    appendLabeledText(lines, "Incident", finding.incident_title);
  }
  if (finding.evidence && finding.evidence.length > 0) {
    appendEvidence(lines, finding.evidence);
  }
  appendLabeledList(lines, "Observed", finding.observed ?? []);
  if (finding.inference) {
    appendLabeledText(lines, "Inference", finding.inference);
  }
  appendLabeledList(lines, "Not verified", finding.not_verified ?? []);
  if (verbose) {
    lines.push(`  Rule: ${finding.rule_id}`);
    lines.push(`  Finding ID: ${finding.finding_id}`);
    if (finding.fingerprint) {
      lines.push(`  Fingerprint: ${finding.fingerprint}`);
    }
    lines.push(
      `  Category: ${finding.category} | Layer: ${finding.layer} | Confidence: ${finding.confidence}`,
    );
    const formattedLocation = formatLocation(finding.location);
    if (formattedLocation) {
      lines.push(`  Location: ${formattedLocation}`);
    }
    if ((finding.affected_locations?.length ?? 0) > 0) {
      lines.push("  Affected locations:");
      for (const location of finding.affected_locations ?? []) {
        const path = toAbsoluteDisplayPath(report.scan_target, location.file_path);
        const locationText = formatLocation({
          field: location.location?.field,
          line: location.location?.line,
          column: location.location?.column,
        });
        lines.push(`    - ${path}${locationText ? ` (${locationText})` : ""}`);
      }
    }
    if (finding.cve) {
      lines.push(`  CVE: ${finding.cve}`);
    }
    lines.push(`  CWE: ${finding.cwe}`);
    if (finding.owasp.length > 0) {
      lines.push(`  OWASP: ${finding.owasp.join(", ")}`);
    }
    if (finding.remediation_actions.length > 0) {
      lines.push(`  Remediation: ${finding.remediation_actions.join(", ")}`);
    }
    appendMetadata(lines, finding.metadata);
  }
  if (finding.layer === "L3" && finding.source_config) {
    const fieldSuffix = finding.source_config.field ? ` (${finding.source_config.field})` : "";
    lines.push(`  source config: ${finding.source_config.file_path}${fieldSuffix}`);
  }
}

export function renderTerminalReport(
  report: CodeGateReport,
  options: TerminalRenderOptions = {},
): string {
  const lines: string[] = [];
  lines.push(`CodeGate v${report.version}`);
  lines.push(`Target: ${report.scan_target}`);
  lines.push(`Findings: ${report.summary.total}`);
  lines.push(`CRITICAL: ${report.summary.by_severity.CRITICAL ?? 0}`);
  lines.push(`HIGH: ${report.summary.by_severity.HIGH ?? 0}`);
  lines.push(`MEDIUM: ${report.summary.by_severity.MEDIUM ?? 0}`);
  lines.push(`LOW: ${report.summary.by_severity.LOW ?? 0}`);
  lines.push(`INFO: ${report.summary.by_severity.INFO ?? 0}`);
  lines.push("");

  if (report.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n");
  }

  const groups = partitionRequestedTargetFindings(report);
  if (groups) {
    lines.push(`Requested URL target findings (${groups.targetFindings.length}):`);
    if (groups.targetFindings.length === 0) {
      lines.push("  none");
    } else {
      for (const finding of groups.targetFindings) {
        appendFinding(lines, report, options, finding);
      }
    }

    if (groups.localFindings.length > 0) {
      lines.push("");
      lines.push(`Additional local host findings (${groups.localFindings.length}):`);
      for (const finding of groups.localFindings) {
        appendFinding(lines, report, options, finding);
      }
    }

    return lines.join("\n");
  }

  for (const finding of report.findings) {
    appendFinding(lines, report, options, finding);
  }

  return lines.join("\n");
}
