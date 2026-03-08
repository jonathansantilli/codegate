import { Box, Text } from "ink";
import { defaultTheme } from "../theme.js";

export interface DeepScanConsentViewProps {
  resourceId: string;
  commandPreview: string;
}

export function DeepScanConsentView(props: DeepScanConsentViewProps) {
  return (
    <Box flexDirection="column" borderStyle="round" paddingX={1}>
      <Text color={defaultTheme.title}>Deep Scan Consent</Text>
      <Text>Resource: {props.resourceId}</Text>
      <Text color={defaultTheme.muted}>Command preview:</Text>
      <Text>{props.commandPreview}</Text>
      <Text>
        Approve this action before execution. No network activity occurs unless consent is granted.
      </Text>
    </Box>
  );
}
