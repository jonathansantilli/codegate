export interface DiffInput {
  filePath: string;
  before: string;
  after: string;
}

export function generateUnifiedDiff(input: DiffInput): string {
  if (input.before === input.after) {
    return "";
  }

  const beforeLines = input.before.split("\n");
  const afterLines = input.after.split("\n");
  const maxLines = Math.max(beforeLines.length, afterLines.length);
  const lines: string[] = [];

  lines.push(`--- a/${input.filePath}`);
  lines.push(`+++ b/${input.filePath}`);
  lines.push("@@");

  for (let index = 0; index < maxLines; index += 1) {
    const beforeLine = beforeLines[index];
    const afterLine = afterLines[index];

    if (beforeLine === afterLine) {
      if (beforeLine !== undefined) {
        lines.push(` ${beforeLine}`);
      }
      continue;
    }

    if (beforeLine !== undefined) {
      lines.push(`-${beforeLine}`);
    }
    if (afterLine !== undefined) {
      lines.push(`+${afterLine}`);
    }
  }

  return lines.join("\n");
}
