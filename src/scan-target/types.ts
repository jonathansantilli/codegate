import type { DiscoveryFormat } from "../types/discovery.js";

export interface ExplicitScanCandidate {
  reportPath: string;
  absolutePath: string;
  format: DiscoveryFormat;
  tool: string;
}

export interface ResolvedScanTarget {
  scanTarget: string;
  displayTarget: string;
  explicitCandidates?: ExplicitScanCandidate[];
  cleanup?: () => Promise<void> | void;
}

export interface ResolveScanTargetInput {
  rawTarget: string;
  cwd: string;
}
