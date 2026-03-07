import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { isLikelyGitRepoUrl, isLikelyHttpUrl } from "./scan-target/helpers.js";
import { cloneGitRepo, downloadRemoteFile, stageLocalFile } from "./scan-target/staging.js";
import type { ResolvedScanTarget, ResolveScanTargetInput } from "./scan-target/types.js";

export type {
  ExplicitScanCandidate,
  ResolvedScanTarget,
  ResolveScanTargetInput,
} from "./scan-target/types.js";

export async function resolveScanTarget(input: ResolveScanTargetInput): Promise<ResolvedScanTarget> {
  const localPath = resolve(input.cwd, input.rawTarget);
  if (existsSync(localPath)) {
    const targetStat = statSync(localPath);
    if (targetStat.isDirectory()) {
      return {
        scanTarget: localPath,
        displayTarget: localPath,
      };
    }
    if (targetStat.isFile()) {
      return stageLocalFile(localPath);
    }
  }

  // Local filesystem paths take precedence; only unresolved HTTP(S) targets are treated as remote artifacts.
  if (!isLikelyHttpUrl(input.rawTarget)) {
    return {
      scanTarget: localPath,
      displayTarget: localPath,
    };
  }

  const url = new URL(input.rawTarget);
  if (isLikelyGitRepoUrl(url)) {
    return cloneGitRepo(input.rawTarget);
  }

  return downloadRemoteFile(input.rawTarget);
}
