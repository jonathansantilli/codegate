import { Box, Text } from "ink";
import type { CodeGateReport } from "../../types/report.js";
import { defaultTheme } from "../theme.js";

export interface SummaryViewProps {
  report: CodeGateReport;
}

function statusLabel(exitCode: number): { text: string; color: string } {
  if (exitCode === 0) {
    return { text: "SAFE", color: defaultTheme.ok };
  }
  if (exitCode === 1) {
    return { text: "WARNINGS", color: defaultTheme.warning };
  }
  return { text: "DANGEROUS", color: defaultTheme.danger };
}

export function SummaryView(props: SummaryViewProps) {
  const status = statusLabel(props.report.summary.exit_code);

  return (
    <Box flexDirection="column" borderStyle="round" paddingX={1}>
      <Text color={defaultTheme.title}>Summary</Text>
      <Text>
        Status: <Text color={status.color}>{status.text}</Text>
      </Text>
      <Text>Total findings: {props.report.summary.total}</Text>
      <Text>Fixable findings: {props.report.summary.fixable}</Text>
      <Text>Suppressed findings: {props.report.summary.suppressed}</Text>
    </Box>
  );
}
