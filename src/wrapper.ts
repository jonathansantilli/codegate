import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { applyConfigPolicy, type CodeGateConfig } from "./config.js";
import { evaluatePostScanGuard, evaluatePreLaunchGuard } from "./commands/run-policy.js";
import { detectTools, type ToolDetection } from "./layer1-discovery/tool-detector.js";
import { renderTerminalReport } from "./reporter/terminal.js";
import { collectScanSurface, runScanEngine } from "./scan.js";
import type { CodeGateReport } from "./types/report.js";

export const RUN_TARGETS = ["claude", "opencode", "codex", "cursor", "windsurf", "kiro"] as const;
export type RunTarget = (typeof RUN_TARGETS)[number];

interface LaunchResult {
  status: number | null;
  error?: Error;
}

export interface RunCommandInput {
  target: string;
  cwd: string;
  version: string;
  config: CodeGateConfig;
  force?: boolean;
  onReport?: (report: CodeGateReport) => void;
  requestWarningProceed?: (report: CodeGateReport) => Promise<boolean> | boolean;
}

interface ScanInput {
  version: string;
  scanTarget: string;
  config: CodeGateConfig;
}

interface SnapshotDeps {
  path: string;
  readFile: (path: string) => string;
  stat: (path: string) => number;
}

export interface WrapperDeps {
  runScan: (input: ScanInput) => Promise<CodeGateReport>;
  detectTools: () => ToolDetection[];
  launchTool: (command: string, args: string[], cwd: string) => LaunchResult;
  collectScanSurface: (scanTarget: string, config: CodeGateConfig) => Promise<string[]> | string[];
  captureSnapshot: (paths: string[]) => Map<string, string>;
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  setExitCode: (code: number) => void;
}

interface RunTargetDefinition {
  label: string;
  detectorTool: ToolDetection["tool"];
  binary: string;
  guiLike: boolean;
}

const TARGETS: Record<RunTarget, RunTargetDefinition> = {
  claude: {
    label: "claude",
    detectorTool: "claude-code",
    binary: "claude",
    guiLike: false,
  },
  opencode: {
    label: "opencode",
    detectorTool: "opencode",
    binary: "opencode",
    guiLike: false,
  },
  codex: {
    label: "codex",
    detectorTool: "codex-cli",
    binary: "codex",
    guiLike: false,
  },
  cursor: {
    label: "cursor",
    detectorTool: "cursor",
    binary: "cursor",
    guiLike: true,
  },
  windsurf: {
    label: "windsurf",
    detectorTool: "windsurf",
    binary: "windsurf",
    guiLike: true,
  },
  kiro: {
    label: "kiro",
    detectorTool: "kiro",
    binary: "kiro",
    guiLike: true,
  },
};

function isRunTarget(value: string): value is RunTarget {
  return RUN_TARGETS.includes(value as RunTarget);
}

function fingerprintFile(deps: SnapshotDeps): string {
  const content = deps.readFile(deps.path);
  const hash = createHash("sha256").update(content).digest("hex");
  const mtime = deps.stat(deps.path);
  return `${mtime}:${hash}`;
}

function defaultCaptureSnapshot(paths: string[]): Map<string, string> {
  const snapshot = new Map<string, string>();
  for (const filePath of paths) {
    try {
      const mode = statSync(filePath).mode;
      if ((mode & 0o170000) !== 0o100000) {
        continue;
      }
      snapshot.set(
        filePath,
        fingerprintFile({
          path: filePath,
          readFile: (path) => readFileSync(path, "utf8"),
          stat: (path) => statSync(path).mtimeMs,
        }),
      );
    } catch {
      continue;
    }
  }

  return snapshot;
}

function snapshotsEqual(before: Map<string, string>, after: Map<string, string>): boolean {
  if (before.size !== after.size) {
    return false;
  }
  for (const [key, value] of before.entries()) {
    if (after.get(key) !== value) {
      return false;
    }
  }
  return true;
}

function expandHomePath(path: string): string {
  if (path === "~") {
    return homedir();
  }
  if (path.startsWith(`~${sep}`) || path.startsWith("~/")) {
    return resolve(homedir(), path.slice(2));
  }
  return path;
}

function isTrustedDirectory(cwd: string, trustedDirectories: string[]): boolean {
  const resolvedCwd = resolve(cwd);

  return trustedDirectories.some((trustedPath) => {
    const resolvedTrusted = resolve(expandHomePath(trustedPath));
    const rel = relative(resolvedTrusted, resolvedCwd);
    return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
  });
}

const defaultWrapperDeps: WrapperDeps = {
  runScan: async (input) =>
    runScanEngine({
      version: input.version,
      scanTarget: input.scanTarget,
      config: input.config,
      scanStatePath: input.config.scan_state_path,
    }),
  detectTools: () => detectTools(),
  collectScanSurface: (scanTarget, config) =>
    collectScanSurface(scanTarget, undefined, {
      includeUserScope: config.scan_user_scope === true,
    }),
  launchTool: (command, args, cwd) => {
    const result = spawnSync(command, args, { cwd, stdio: "inherit" });
    return {
      status: result.status,
      error: result.error ?? undefined,
    };
  },
  captureSnapshot: (paths) => defaultCaptureSnapshot(paths),
  stdout: (message) => {
    process.stdout.write(`${message}\n`);
  },
  stderr: (message) => {
    process.stderr.write(`${message}\n`);
  },
  setExitCode: (code) => {
    process.exitCode = code;
  },
};

export async function executeWrapperRun(
  input: RunCommandInput,
  deps: WrapperDeps = defaultWrapperDeps,
): Promise<void> {
  const normalizedTarget = input.target.trim().toLowerCase();
  if (!isRunTarget(normalizedTarget)) {
    deps.stderr(
      `Unknown tool: ${input.target}. Valid targets: ${RUN_TARGETS.join(", ")}.`,
    );
    deps.setExitCode(3);
    return;
  }

  const target = TARGETS[normalizedTarget];
  const detection = deps
    .detectTools()
    .find((tool) => tool.tool === target.detectorTool && tool.installed);

  if (!detection) {
    deps.stderr(`${target.label} is not installed.`);
    deps.setExitCode(3);
    return;
  }

  const resolvedCwd = resolve(input.cwd);
  const preScanSurface = await deps.collectScanSurface(input.cwd, input.config);
  const preScanSnapshot = deps.captureSnapshot(preScanSurface);

  const rawReport = await deps.runScan({
    version: input.version,
    scanTarget: input.cwd,
    config: input.config,
  });
  const report = applyConfigPolicy(rawReport, input.config);
  if (input.onReport) {
    input.onReport(report);
  } else {
    deps.stdout(renderTerminalReport(report));
  }

  const scanSurface = await deps.collectScanSurface(input.cwd, input.config);
  const scanSnapshot = deps.captureSnapshot(scanSurface);
  const postScanDecision = evaluatePostScanGuard({
    report,
    scanSurfaceChanged: !snapshotsEqual(preScanSnapshot, scanSnapshot),
    force: input.force === true,
    autoProceedBelowThreshold: input.config.auto_proceed_below_threshold === true,
    insideTrustedDirectory: isTrustedDirectory(resolvedCwd, input.config.trusted_directories),
  });
  if (postScanDecision.kind === "block") {
    const writer = postScanDecision.stream === "stderr" ? deps.stderr : deps.stdout;
    writer(postScanDecision.message);
    deps.setExitCode(postScanDecision.exitCode);
    return;
  }

  if (postScanDecision.kind === "prompt") {
    if (!input.requestWarningProceed) {
      deps.stderr(
        "Warning findings detected. Re-run with --force to launch non-interactively or enable auto_proceed_below_threshold.",
      );
      deps.setExitCode(1);
      return;
    }

    const approved = await input.requestWarningProceed(report);
    if (!approved) {
      deps.stdout("Launch cancelled because warning findings require confirmation.");
      deps.setExitCode(1);
      return;
    }
  }

  const launchSurface = await deps.collectScanSurface(input.cwd, input.config);
  const launchSnapshot = deps.captureSnapshot(launchSurface);
  const preLaunchDecision = evaluatePreLaunchGuard({
    launchSurfaceChanged: !snapshotsEqual(scanSnapshot, launchSnapshot),
  });
  if (preLaunchDecision.kind === "block") {
    const writer = preLaunchDecision.stream === "stderr" ? deps.stderr : deps.stdout;
    writer(preLaunchDecision.message);
    deps.setExitCode(preLaunchDecision.exitCode);
    return;
  }

  if (target.guiLike && detection.source !== "path") {
    deps.stdout(
      `Scan complete. ${target.label} appears installed without a CLI launcher. Launch it manually.`,
    );
    deps.setExitCode(report.summary.exit_code);
    return;
  }

  const args = target.guiLike ? ["."] : [];
  const launched = deps.launchTool(target.binary, args, input.cwd);
  if (launched.status !== 0 || launched.error) {
    const reason = launched.error?.message ?? `exit status ${launched.status ?? "unknown"}`;
    deps.stderr(`Failed to launch ${target.label}: ${reason}`);
    deps.setExitCode(3);
    return;
  }

  deps.setExitCode(report.summary.exit_code);
}
