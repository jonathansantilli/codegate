import { Box, Text } from "ink";
import type { CodeGateReport } from "../../types/report.js";
import { toAbsoluteDisplayPath } from "../../path-display.js";
import { defaultTheme } from "../theme.js";

export interface DashboardViewProps {
  report: CodeGateReport;
  notices?: string[];
}

export function DashboardView(props: DashboardViewProps) {
  const visibleFindings = props.report.findings.slice(0, 5);

  return (
    <Box flexDirection="column" borderStyle="round" paddingX={1}>
      <Text color={defaultTheme.title}>CodeGate v{props.report.version}</Text>
      <Text color={defaultTheme.muted}>Target: {props.report.scan_target}</Text>
      <Box marginTop={1} flexDirection="column">
        <Text>Installed tools: {props.report.tools_detected.join(", ") || "none"}</Text>
        <Text>
          Findings: {props.report.summary.total} (CRITICAL {props.report.summary.by_severity.CRITICAL ?? 0}, HIGH{" "}
          {props.report.summary.by_severity.HIGH ?? 0}, MEDIUM {props.report.summary.by_severity.MEDIUM ?? 0}, LOW{" "}
          {props.report.summary.by_severity.LOW ?? 0}, INFO {props.report.summary.by_severity.INFO ?? 0})
        </Text>
        {props.notices && props.notices.length > 0 ? (
          <Box marginTop={1} flexDirection="column">
            <Text color={defaultTheme.title}>Deep scan:</Text>
            {props.notices.map((notice, index) => (
              <Text key={`notice-${index}`} color={defaultTheme.muted}>
                {notice}
              </Text>
            ))}
          </Box>
        ) : null}
      </Box>
      {visibleFindings.length > 0 ? (
        <Box marginTop={1} flexDirection="column">
          <Text color={defaultTheme.title}>Findings detail:</Text>
          {visibleFindings.map((finding) => (
            <Box key={finding.finding_id} flexDirection="column" marginTop={1}>
              <Text>
                [{finding.severity}] {toAbsoluteDisplayPath(props.report.scan_target, finding.file_path)}
              </Text>
              <Text>{finding.description}</Text>
              {finding.evidence ? (
                <Box flexDirection="column">
                  <Text>Evidence:</Text>
                  {finding.evidence.split("\n").map((line, index) => (
                    <Text key={`${finding.finding_id}-evidence-${index}`}>{line}</Text>
                  ))}
                </Box>
              ) : null}
            </Box>
          ))}
          {props.report.findings.length > visibleFindings.length ? (
            <Text color={defaultTheme.muted}>
              ...and {props.report.findings.length - visibleFindings.length} more findings
            </Text>
          ) : null}
        </Box>
      ) : null}
    </Box>
  );
}
