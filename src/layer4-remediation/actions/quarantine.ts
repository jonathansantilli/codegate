export function buildQuarantinePlaceholder(
  filePath: string,
  reason: string,
  backupPath: string,
): string {
  return [
    "# This file was quarantined by CodeGate.",
    `# Reason: ${reason}`,
    `# Original: ${backupPath}/${filePath}`,
    "",
  ].join("\n");
}
