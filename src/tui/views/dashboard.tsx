import { Box, Text } from "ink";
import type { CodeGateReport } from "../../types/report.js";
import { toAbsoluteDisplayPath } from "../../path-display.js";
import { partitionRequestedTargetFindings } from "../../report/requested-target-findings.js";
import { defaultTheme } from "../theme.js";

export interface DashboardViewProps {
  report: CodeGateReport;
  notices?: string[];
}

const FINDINGS_PER_SECTION_LIMIT = 5;

function FindingBlock(props: {
  report: CodeGateReport;
  finding: CodeGateReport["findings"][number];
}) {
  return (
    <Box key={props.finding.finding_id} flexDirection="column" marginTop={1}>
      <Text>
        [{props.finding.severity}]{" "}
        {toAbsoluteDisplayPath(props.report.scan_target, props.finding.file_path)}
      </Text>
      <Text>{props.finding.description}</Text>
      {props.finding.evidence ? (
        <Box flexDirection="column">
          <Text>Evidence:</Text>
          {props.finding.evidence.split("\n").map((line, index) => (
            <Text key={`${props.finding.finding_id}-evidence-${index}`}>{line}</Text>
          ))}
        </Box>
      ) : null}
    </Box>
  );
}

function FindingsSection(props: {
  title: string;
  report: CodeGateReport;
  findings: CodeGateReport["findings"];
}) {
  const visibleFindings = props.findings.slice(0, FINDINGS_PER_SECTION_LIMIT);
  const remaining = props.findings.length - visibleFindings.length;

  return (
    <Box marginTop={1} flexDirection="column">
      <Text color={defaultTheme.title}>
        {props.title} ({props.findings.length}):
      </Text>
      {visibleFindings.length === 0 ? (
        <Text color={defaultTheme.muted}>none</Text>
      ) : (
        visibleFindings.map((finding) => (
          <FindingBlock key={finding.finding_id} report={props.report} finding={finding} />
        ))
      )}
      {remaining > 0 ? (
        <Text color={defaultTheme.muted}>...and {remaining} more findings</Text>
      ) : null}
    </Box>
  );
}

export function DashboardView(props: DashboardViewProps) {
  const groupedFindings = partitionRequestedTargetFindings(props.report);

  return (
    <Box flexDirection="column" borderStyle="round" paddingX={1}>
      <Text color={defaultTheme.title}>CodeGate v{props.report.version}</Text>
      <Text color={defaultTheme.muted}>Target: {props.report.scan_target}</Text>
      <Box marginTop={1} flexDirection="column">
        <Text>Installed tools: {props.report.tools_detected.join(", ") || "none"}</Text>
        <Text>
          Findings: {props.report.summary.total} (CRITICAL{" "}
          {props.report.summary.by_severity.CRITICAL ?? 0}, HIGH{" "}
          {props.report.summary.by_severity.HIGH ?? 0}, MEDIUM{" "}
          {props.report.summary.by_severity.MEDIUM ?? 0}, LOW{" "}
          {props.report.summary.by_severity.LOW ?? 0}, INFO{" "}
          {props.report.summary.by_severity.INFO ?? 0})
        </Text>
        {props.notices && props.notices.length > 0 ? (
          <Box marginTop={1} flexDirection="column">
            <Text color={defaultTheme.title}>Notes:</Text>
            {props.notices.map((notice, index) => (
              <Text key={`notice-${index}`} color={defaultTheme.muted}>
                {notice}
              </Text>
            ))}
          </Box>
        ) : null}
      </Box>
      {props.report.findings.length > 0 ? (
        <Box marginTop={1} flexDirection="column">
          <Text color={defaultTheme.title}>Findings detail:</Text>
          {groupedFindings ? (
            <>
              <FindingsSection
                title="Requested URL target findings"
                report={props.report}
                findings={groupedFindings.targetFindings}
              />
              {groupedFindings.localFindings.length > 0 ? (
                <FindingsSection
                  title="Additional local host findings"
                  report={props.report}
                  findings={groupedFindings.localFindings}
                />
              ) : null}
            </>
          ) : (
            <FindingsSection
              title="Findings"
              report={props.report}
              findings={props.report.findings}
            />
          )}
        </Box>
      ) : null}
    </Box>
  );
}
