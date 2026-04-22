import type { DiscoveryFormat } from "../types/discovery.js";

export interface ExplicitScanCandidate {
  reportPath: string;
  absolutePath: string;
  format: DiscoveryFormat;
  tool: string;
  textContent?: string;
}

export interface ResolvedScanTarget {
  scanTarget: string;
  displayTarget: string;
  explicitCandidates?: ExplicitScanCandidate[];
  /**
   * `true` when the raw input was a local file that got staged into a
   * temp directory. This is the signal the CLI uses to disable the
   * user-scope walk, regardless of whether `explicitCandidates` could be
   * inferred for the file (an XML / binary / unrecognised extension
   * would still benefit from the scope guard).
   */
  stagedFromLocalFile?: boolean;
  cleanup?: () => Promise<void> | void;
}

export interface ResolveScanTargetInput {
  rawTarget: string;
  cwd: string;
  preferredSkill?: string;
  interactive?: boolean;
  requestSkillSelection?: (options: string[]) => Promise<string | null> | string | null;
}
