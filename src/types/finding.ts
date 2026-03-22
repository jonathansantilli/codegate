export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_CATEGORIES = [
  "ENV_OVERRIDE",
  "COMMAND_EXEC",
  "CONSENT_BYPASS",
  "RULE_INJECTION",
  "IDE_SETTINGS",
  "SYMLINK_ESCAPE",
  "GIT_HOOK",
  "CONFIG_PRESENT",
  "PARSE_ERROR",
  "CONFIG_CHANGE",
  "NEW_SERVER",
  "TOXIC_FLOW",
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export type FindingLayer = "L1" | "L2" | "L3";
export type FindingConfidence = "HIGH" | "MEDIUM" | "LOW";

export interface FindingLocation {
  field?: string;
  line?: number;
  column?: number;
}

export interface FindingSourceConfig {
  file_path: string;
  field?: string;
}

export interface FindingMetadata {
  sources?: string[];
  sinks?: string[];
  referenced_secrets?: string[];
  risk_tags?: string[];
  origin?: string;
}

export interface AffectedLocation {
  file_path: string;
  location?: FindingLocation;
}

export interface Finding {
  rule_id: string;
  finding_id: string;
  fingerprint?: string;
  severity: Severity;
  category: FindingCategory;
  layer: FindingLayer;
  file_path: string;
  location: FindingLocation;
  affected_locations?: AffectedLocation[] | null;
  description: string;
  affected_tools: string[];
  cve?: string | null;
  owasp: string[];
  cwe: string;
  confidence: FindingConfidence;
  fixable: boolean;
  remediation_actions: string[];
  metadata?: FindingMetadata | null;
  evidence?: string | null;
  observed?: string[] | null;
  inference?: string | null;
  not_verified?: string[] | null;
  incident_id?: string | null;
  incident_title?: string | null;
  incident_primary?: boolean | null;
  source_config?: FindingSourceConfig | null;
  suppressed: boolean;
}
