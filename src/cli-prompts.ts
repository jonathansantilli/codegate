import { createInterface } from "node:readline/promises";
import type {
  DeepAgentOption,
  MetaAgentCommandConsentContext,
  RemediationConsentContext,
} from "./commands/scan-command.js";
import type { DeepScanResource } from "./pipeline.js";

function commandPreview(value: string): string {
  const maxLength = 900;
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength)}\n...[command preview truncated ${value.length - maxLength} chars]`;
}

export async function promptDeepScanConsent(resource: DeepScanResource): Promise<boolean> {
  const preview = resource.commandPreview.length > 0 ? `\n${resource.commandPreview}` : "";
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  try {
    const answer = await rl.question(`Approve deep scan for ${resource.id}?${preview}\n[y/N]: `);
    return /^y(es)?$/iu.test(answer.trim());
  } finally {
    rl.close();
  }
}

export async function promptDeepAgentSelection(options: DeepAgentOption[]): Promise<DeepAgentOption | null> {
  if (options.length === 0) {
    return null;
  }

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  const optionLines = options.map(
    (option, index) => `  ${index + 1}. ${option.label} (${option.id}) -> ${option.binary}`,
  );

  const prompt = [
    "Select a deep-scan meta-agent:",
    ...optionLines,
    `Choose [1-${options.length}] or press Enter for 1 (q to skip): `,
  ].join("\n");

  try {
    const answer = (await rl.question(prompt)).trim().toLowerCase();
    if (answer === "q" || answer === "skip") {
      return null;
    }
    if (answer.length === 0) {
      return options[0] ?? null;
    }
    const numeric = Number.parseInt(answer, 10);
    if (Number.isNaN(numeric) || numeric < 1 || numeric > options.length) {
      return options[0] ?? null;
    }
    return options[numeric - 1] ?? null;
  } finally {
    rl.close();
  }
}

export async function promptMetaAgentCommandConsent(context: MetaAgentCommandConsentContext): Promise<boolean> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const subjectLabel = context.localFile?.reportPath ?? context.resource?.id ?? "analysis target";

  const prompt = [
    `Deep scan command for ${subjectLabel}`,
    `Agent: ${context.agent.label} (${context.agent.binary})`,
    "Command preview:",
    commandPreview(context.command.preview),
    "Approve command execution? [y/N]: ",
  ].join("\n");

  try {
    const answer = await rl.question(prompt);
    return /^y(es)?$/iu.test(answer.trim());
  } finally {
    rl.close();
  }
}

export async function promptRemediationConsent(context: RemediationConsentContext): Promise<boolean> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = [
    `Remediation will modify files under: ${context.scanTarget}`,
    `Findings in scope: ${context.totalFindings} (${context.fixableFindings} fixable, ${context.criticalFindings} critical)`,
    "A backup session will be created in .codegate-backup/ before changes.",
    "Proceed with remediation? [y/N]: ",
  ].join("\n");

  try {
    const answer = await rl.question(prompt);
    return /^y(es)?$/iu.test(answer.trim());
  } finally {
    rl.close();
  }
}
