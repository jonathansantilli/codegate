import type { FindingLocation, FindingMetadata } from "../types/finding.js";
import type { CodeGateReport } from "../types/report.js";

function escapePipes(value: string): string {
  return value.replaceAll("|", "\\|");
}

function formatLocation(location: FindingLocation): string {
  const parts: string[] = [];

  if (location.field) {
    parts.push(location.field);
  }
  if (typeof location.line === "number") {
    parts.push(`line ${location.line}`);
  }
  if (typeof location.column === "number") {
    parts.push(`col ${location.column}`);
  }

  return parts.join(", ") || "-";
}

function formatMetadata(metadata: FindingMetadata | null | undefined): string {
  if (!metadata) {
    return "-";
  }

  const parts: string[] = [];
  if (metadata.sources && metadata.sources.length > 0) {
    parts.push(`sources=${metadata.sources.join(", ")}`);
  }
  if (metadata.sinks && metadata.sinks.length > 0) {
    parts.push(`sinks=${metadata.sinks.join(", ")}`);
  }
  if (metadata.referenced_secrets && metadata.referenced_secrets.length > 0) {
    parts.push(`referenced_secrets=${metadata.referenced_secrets.join(", ")}`);
  }
  if (metadata.risk_tags && metadata.risk_tags.length > 0) {
    parts.push(`risk_tags=${metadata.risk_tags.join(", ")}`);
  }
  if (metadata.origin) {
    parts.push(`origin=${metadata.origin}`);
  }

  return parts.length > 0 ? parts.join("; ") : "-";
}

export function renderMarkdownReport(report: CodeGateReport): string {
  const lines: string[] = [];

  lines.push("# CodeGate Report");
  lines.push("");
  lines.push(`- Version: \`${report.version}\``);
  lines.push(`- Target: \`${report.scan_target}\``);
  lines.push(`- Timestamp: \`${report.timestamp}\``);
  lines.push(`- KB Version: \`${report.kb_version}\``);
  lines.push(`- Exit Code: \`${report.summary.exit_code}\``);
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("| --- | --- |");
  lines.push(`| Total findings | ${report.summary.total} |`);
  lines.push(`| CRITICAL | ${report.summary.by_severity.CRITICAL ?? 0} |`);
  lines.push(`| HIGH | ${report.summary.by_severity.HIGH ?? 0} |`);
  lines.push(`| MEDIUM | ${report.summary.by_severity.MEDIUM ?? 0} |`);
  lines.push(`| LOW | ${report.summary.by_severity.LOW ?? 0} |`);
  lines.push(`| INFO | ${report.summary.by_severity.INFO ?? 0} |`);
  lines.push(`| Fixable | ${report.summary.fixable} |`);
  lines.push(`| Suppressed | ${report.summary.suppressed} |`);
  lines.push("");

  lines.push("## Findings");
  lines.push("");

  if (report.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n");
  }

  lines.push("| Severity | Category | File | Location | Description | Fingerprint | Metadata |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- |");

  for (const finding of report.findings) {
    lines.push(
      `| ${finding.severity} | ${finding.category} | \`${escapePipes(finding.file_path)}\` | ${escapePipes(formatLocation(finding.location))} | ${escapePipes(finding.description)} | ${escapePipes(finding.fingerprint ?? "-")} | ${escapePipes(formatMetadata(finding.metadata))} |`,
    );
  }

  return lines.join("\n");
}
