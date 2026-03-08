import type { FindingLocation } from "../types/finding.js";
import type { CodeGateReport } from "../types/report.js";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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

function renderSummary(report: CodeGateReport): string {
  return `
    <ul>
      <li><strong>Total findings:</strong> ${report.summary.total}</li>
      <li><strong>CRITICAL:</strong> ${report.summary.by_severity.CRITICAL ?? 0}</li>
      <li><strong>HIGH:</strong> ${report.summary.by_severity.HIGH ?? 0}</li>
      <li><strong>MEDIUM:</strong> ${report.summary.by_severity.MEDIUM ?? 0}</li>
      <li><strong>LOW:</strong> ${report.summary.by_severity.LOW ?? 0}</li>
      <li><strong>INFO:</strong> ${report.summary.by_severity.INFO ?? 0}</li>
      <li><strong>Fixable:</strong> ${report.summary.fixable}</li>
      <li><strong>Suppressed:</strong> ${report.summary.suppressed}</li>
      <li><strong>Exit code:</strong> ${report.summary.exit_code}</li>
    </ul>
  `;
}

function renderFindings(report: CodeGateReport): string {
  if (report.findings.length === 0) {
    return "<p>No findings.</p>";
  }

  const rows = report.findings
    .map((finding) => {
      const location = formatLocation(finding.location);
      return `
        <tr>
          <td>${escapeHtml(finding.severity)}</td>
          <td>${escapeHtml(finding.category)}</td>
          <td>${escapeHtml(finding.file_path)}</td>
          <td>${escapeHtml(location)}</td>
          <td>${escapeHtml(finding.description)}</td>
        </tr>
      `;
    })
    .join("\n");

  return `
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Category</th>
          <th>File</th>
          <th>Location</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}

export function renderHtmlReport(report: CodeGateReport): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>CodeGate Report</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; color: #0f172a; }
      h1, h2 { margin: 0 0 12px 0; }
      .meta { margin: 0 0 20px 0; color: #334155; }
      table { border-collapse: collapse; width: 100%; margin-top: 12px; }
      th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; vertical-align: top; }
      th { background: #f1f5f9; }
      code { background: #f8fafc; padding: 2px 4px; border-radius: 4px; }
    </style>
  </head>
  <body>
    <h1>CodeGate Report</h1>
    <p class="meta">
      Version <code>${escapeHtml(report.version)}</code> |
      Target <code>${escapeHtml(report.scan_target)}</code> |
      KB <code>${escapeHtml(report.kb_version)}</code> |
      Generated <code>${escapeHtml(report.timestamp)}</code>
    </p>
    <h2>Summary</h2>
    ${renderSummary(report)}
    <h2>Findings</h2>
    ${renderFindings(report)}
  </body>
</html>`;
}
