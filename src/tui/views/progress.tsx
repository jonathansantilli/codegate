import { Box, Text } from "ink";
import { defaultTheme } from "../theme.js";

export interface ProgressViewProps {
  progressMessage?: string;
}

export function ProgressView(props: ProgressViewProps) {
  return (
    <Box flexDirection="column" borderStyle="round" paddingX={1}>
      <Text color={defaultTheme.title}>Progress</Text>
      <Text>{props.progressMessage ?? "Scanning..."}</Text>
    </Box>
  );
}
