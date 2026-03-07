import type { CodeGateReport } from "../types/report.js";

interface BlockDecision {
  kind: "block";
  exitCode: number;
  message: string;
  stream: "stdout" | "stderr";
}

interface PromptDecision {
  kind: "prompt";
}

interface AllowDecision {
  kind: "allow";
}

export type RunPolicyDecision = BlockDecision | PromptDecision | AllowDecision;

export interface PostScanGuardInput {
  report: CodeGateReport;
  scanSurfaceChanged: boolean;
  force: boolean;
  autoProceedBelowThreshold: boolean;
  insideTrustedDirectory: boolean;
}

export interface PreLaunchGuardInput {
  launchSurfaceChanged: boolean;
}

const RESCAN_MESSAGE = "Config files changed after scan. Re-run `codegate scan` before launch.";

export function evaluatePostScanGuard(input: PostScanGuardInput): RunPolicyDecision {
  if (input.report.summary.exit_code === 2) {
    return {
      kind: "block",
      exitCode: 2,
      message: "Dangerous findings detected. Resolve issues before launching tool.",
      stream: "stderr",
    };
  }

  if (input.scanSurfaceChanged) {
    return {
      kind: "block",
      exitCode: 3,
      message: RESCAN_MESSAGE,
      stream: "stderr",
    };
  }

  const needsWarningProceed =
    input.report.summary.exit_code === 1 &&
    input.report.findings.length > 0 &&
    input.force !== true &&
    input.autoProceedBelowThreshold !== true &&
    !input.insideTrustedDirectory;

  if (needsWarningProceed) {
    return { kind: "prompt" };
  }

  return { kind: "allow" };
}

export function evaluatePreLaunchGuard(input: PreLaunchGuardInput): RunPolicyDecision {
  if (input.launchSurfaceChanged) {
    return {
      kind: "block",
      exitCode: 3,
      message: RESCAN_MESSAGE,
      stream: "stderr",
    };
  }

  return { kind: "allow" };
}
