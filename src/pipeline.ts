import {
  runStaticEngine,
  type StaticEngineConfig,
  type StaticFileInput,
} from "./layer2-static/engine.js";
import { createEmptyReport, type CodeGateReport } from "./types/report.js";
import type { GitHookEntry } from "./layer2-static/detectors/git-hooks.js";
import type { SymlinkEscapeEntry } from "./layer2-static/detectors/symlink.js";
import type { ResourceFetchResult, ResourceRequest } from "./layer3-dynamic/resource-fetcher.js";
import {
  scanToolDescriptions,
  type ToolDescription,
} from "./layer3-dynamic/tool-description-scanner.js";
import { detectToxicFlows, type ToxicToolClass } from "./layer3-dynamic/toxic-flow.js";
import {
  deriveRegistryFindings,
  type RegistryHeuristicsOptions,
} from "./layer3-dynamic/registry-findings.js";
import { applyReportSummary } from "./report-summary.js";
import { withFindingFingerprint } from "./report/finding-fingerprint.js";
import type { Finding } from "./types/finding.js";

export interface StaticPipelineInput {
  version: string;
  kbVersion: string;
  scanTarget: string;
  toolsDetected: string[];
  projectRoot: string;
  files: StaticFileInput[];
  symlinkEscapes: SymlinkEscapeEntry[];
  hooks: GitHookEntry[];
  config: StaticEngineConfig;
}

export interface DeepScanResource {
  id: string;
  request: ResourceRequest;
  commandPreview: string;
}

export interface DeepScanOutcome {
  resourceId: string;
  approved: boolean;
  status:
    | "skipped_without_consent"
    | "ok"
    | "auth_failure"
    | "timeout"
    | "network_error"
    | "command_error";
  result?: ResourceFetchResult;
}

interface Layer3ResponseFinding {
  id?: string;
  severity?: string;
  category?: string;
  description?: string;
  file_path?: string;
  field?: string;
  cwe?: string;
  owasp?: string[];
  confidence?: string;
  evidence?: string;
  fixable?: boolean;
  remediation_actions?: string[];
  source_config?: {
    file_path: string;
    field?: string;
  };
}

interface Layer3ToolEntry {
  name: string;
  description: string;
  classifications?: ToxicToolClass[];
}

type ToolClassificationMap = Record<string, ToxicToolClass[]>;

export async function runStaticPipeline(input: StaticPipelineInput): Promise<CodeGateReport> {
  const findings = (
    await runStaticEngine({
      projectRoot: input.projectRoot,
      files: input.files,
      symlinkEscapes: input.symlinkEscapes,
      hooks: input.hooks,
      config: input.config,
    })
  ).map(withFindingFingerprint);

  const report = createEmptyReport({
    version: input.version,
    kbVersion: input.kbVersion,
    scanTarget: input.scanTarget,
    toolsDetected: input.toolsDetected,
    exitCode: 0,
  });

  return applyReportSummary({
    ...report,
    findings,
  });
}

function parseSeverity(value: string | undefined): Finding["severity"] {
  if (value === "CRITICAL" || value === "HIGH" || value === "MEDIUM" || value === "LOW") {
    return value;
  }
  return "INFO";
}

function parseConfidence(value: string | undefined): Finding["confidence"] {
  if (value === "HIGH" || value === "MEDIUM") {
    return value;
  }
  return "LOW";
}

function parseCategory(value: string | undefined): Finding["category"] {
  if (
    value === "ENV_OVERRIDE" ||
    value === "COMMAND_EXEC" ||
    value === "CONSENT_BYPASS" ||
    value === "RULE_INJECTION" ||
    value === "IDE_SETTINGS" ||
    value === "SYMLINK_ESCAPE" ||
    value === "GIT_HOOK" ||
    value === "CONFIG_PRESENT" ||
    value === "CONFIG_CHANGE" ||
    value === "NEW_SERVER" ||
    value === "TOXIC_FLOW"
  ) {
    return value;
  }
  return "PARSE_ERROR";
}

function parseLayer3Response(resourceId: string, metadata: unknown): Finding[] {
  if (!metadata || typeof metadata !== "object") {
    return [];
  }

  const root = metadata as Record<string, unknown>;
  if (!Array.isArray(root.findings)) {
    return [];
  }

  return root.findings
    .filter((item): item is Layer3ResponseFinding => typeof item === "object" && item !== null)
    .map((item, index) => {
      const findingId = item.id ?? `L3-${resourceId}-${index}`;
      return withFindingFingerprint({
        rule_id: item.id ?? "layer3-analysis-finding",
        finding_id: findingId,
        severity: parseSeverity(item.severity),
        category: parseCategory(item.category),
        layer: "L3" as const,
        file_path: item.file_path ?? resourceId,
        location: { field: item.field },
        description: item.description ?? "Layer 3 analysis finding",
        affected_tools: [],
        cve: null,
        owasp: Array.isArray(item.owasp) ? item.owasp : [],
        cwe: item.cwe ?? "CWE-20",
        confidence: parseConfidence(item.confidence),
        evidence: typeof item.evidence === "string" ? item.evidence : null,
        fixable: item.fixable ?? false,
        remediation_actions: item.remediation_actions ?? [],
        source_config: item.source_config ?? null,
        suppressed: false,
      });
    });
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function parseToxicClass(value: string): ToxicToolClass | null {
  if (
    value === "untrusted_input" ||
    value === "sensitive_access" ||
    value === "exfiltration_sink"
  ) {
    return value;
  }
  return null;
}

function parseToxicClasses(value: unknown): ToxicToolClass[] {
  if (typeof value === "string") {
    const parsed = parseToxicClass(value);
    return parsed ? [parsed] : [];
  }
  if (!Array.isArray(value)) {
    return [];
  }
  const classes: ToxicToolClass[] = [];
  for (const item of value) {
    if (typeof item !== "string") {
      continue;
    }
    const parsed = parseToxicClass(item);
    if (parsed) {
      classes.push(parsed);
    }
  }
  return classes;
}

function parseToolEntries(metadata: unknown): Layer3ToolEntry[] {
  const root = asRecord(metadata);
  if (!root || !Array.isArray(root.tools)) {
    return [];
  }

  return root.tools
    .map((entry) => asRecord(entry))
    .filter((entry): entry is Record<string, unknown> => entry !== null)
    .map((entry) => {
      const name = typeof entry.name === "string" ? entry.name : "";
      const description = typeof entry.description === "string" ? entry.description : "";
      const classifications = parseToxicClasses(entry.classifications ?? entry.classification);
      return { name, description, classifications };
    })
    .filter((entry) => entry.name.length > 0 && entry.description.length > 0);
}

function parseToolClassifications(
  metadata: unknown,
  tools: Layer3ToolEntry[],
): ToolClassificationMap {
  const map: ToolClassificationMap = {};
  const root = asRecord(metadata);

  for (const tool of tools) {
    if (!tool.classifications || tool.classifications.length === 0) {
      continue;
    }
    map[tool.name] = tool.classifications;
  }

  const classificationRoot = asRecord(root?.tool_classifications ?? root?.toolClassifications);
  if (!classificationRoot) {
    return map;
  }

  for (const [toolName, value] of Object.entries(classificationRoot)) {
    const parsed = parseToxicClasses(value);
    if (parsed.length === 0) {
      continue;
    }
    map[toolName] = parsed;
  }

  return map;
}

interface Layer3ToolAnalysis {
  findings: Finding[];
  toolDescriptions: ToolDescription[];
  knownClassifications: ToolClassificationMap;
}

function analyzeLayer3Tools(
  resourceId: string,
  metadata: unknown,
  options: { unicodeAnalysis?: boolean } = {},
): Layer3ToolAnalysis {
  const toolEntries = parseToolEntries(metadata);
  if (toolEntries.length === 0) {
    return { findings: [], toolDescriptions: [], knownClassifications: {} };
  }

  const toolDescriptions: ToolDescription[] = toolEntries.map((entry) => ({
    name: entry.name,
    description: entry.description,
  }));
  const knownClassifications = parseToolClassifications(metadata, toolEntries);

  return {
    findings: [
      ...scanToolDescriptions({
        serverId: resourceId,
        tools: toolDescriptions,
        unicodeAnalysis: options.unicodeAnalysis,
      }).map(withFindingFingerprint),
      ...detectToxicFlows({
        scopeId: resourceId,
        tools: toolDescriptions,
        knownClassifications,
      }).map(withFindingFingerprint),
    ],
    toolDescriptions,
    knownClassifications,
  };
}

function layer3ErrorFinding(
  resourceId: string,
  status: DeepScanOutcome["status"],
  description: string,
): Finding {
  const severity: Finding["severity"] =
    status === "timeout" ? "MEDIUM" : status === "skipped_without_consent" ? "INFO" : "LOW";

  return withFindingFingerprint({
    rule_id: `layer3-${status}`,
    finding_id: `L3-${status}-${resourceId}`,
    severity,
    category: "PARSE_ERROR",
    layer: "L3",
    file_path: resourceId,
    location: { field: "layer3" },
    description,
    affected_tools: [],
    cve: null,
    owasp: [],
    cwe: "CWE-20",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    suppressed: false,
  });
}

export interface Layer3FindingOptions {
  unicodeAnalysis?: boolean;
  registryHeuristics?: RegistryHeuristicsOptions;
}

export function layer3OutcomesToFindings(
  outcomes: DeepScanOutcome[],
  options: Layer3FindingOptions = {},
): Finding[] {
  const findings: Finding[] = [];
  const workspaceTools: ToolDescription[] = [];
  const workspaceClassifications: ToolClassificationMap = {};
  const workspaceOrigins: Record<string, string> = {};
  const contributingServers = new Set<string>();

  const addWorkspaceTools = (resourceId: string, analysis: Layer3ToolAnalysis): void => {
    for (const tool of analysis.toolDescriptions) {
      // Keep workspace tool names unique across servers so origins stay unambiguous.
      const uniqueName =
        workspaceOrigins[tool.name] === undefined ? tool.name : `${tool.name}@${resourceId}`;
      workspaceTools.push({ name: uniqueName, description: tool.description });
      workspaceOrigins[uniqueName] = resourceId;
      const classifications = analysis.knownClassifications[tool.name];
      if (classifications && classifications.length > 0) {
        workspaceClassifications[uniqueName] = classifications;
      }
    }
    if (analysis.toolDescriptions.length > 0) {
      contributingServers.add(resourceId);
    }
  };

  for (const outcome of outcomes) {
    if (!outcome.approved || outcome.status === "skipped_without_consent") {
      findings.push(
        layer3ErrorFinding(
          outcome.resourceId,
          "skipped_without_consent",
          "Deep scan skipped because consent was not granted",
        ),
      );
      continue;
    }

    if (outcome.status !== "ok" || !outcome.result) {
      findings.push(
        layer3ErrorFinding(
          outcome.resourceId,
          outcome.status,
          `Deep scan failed with status: ${outcome.status}`,
        ),
      );
      continue;
    }

    const parsed = parseLayer3Response(outcome.resourceId, outcome.result.metadata);
    const analysis = analyzeLayer3Tools(outcome.resourceId, outcome.result.metadata, options);
    addWorkspaceTools(outcome.resourceId, analysis);
    const registryFindings = deriveRegistryFindings(
      outcome.resourceId,
      outcome.result.metadata,
      options.registryHeuristics,
    ).map(withFindingFingerprint);
    const combined = [...parsed, ...analysis.findings, ...registryFindings];

    // If a Layer 3 resource was fetched successfully but carries no
    // actionable metadata (no `findings[]`, no `tools[]`), that is not an
    // issue with the scan target itself — it usually means the default
    // no-outbound-call resource executor recorded only a URL stub, or that
    // a host-configured MCP endpoint simply returned an unrecognised
    // payload. Previously we emitted a LOW `layer3-network_error`
    // "schema mismatch" finding whose `file_path` was the remote URL,
    // which leaked host-level noise into every per-target scan report.
    // Fetch-level anomalies that are unrelated to the scan target are now
    // dropped silently for all resource kinds.
    if (combined.length === 0) {
      continue;
    }
    findings.push(...combined);
  }

  // Cross-server pass: a toxic chain whose links live on different servers
  // is invisible to the per-server analysis above.
  if (contributingServers.size >= 2) {
    findings.push(
      ...detectToxicFlows({
        scopeId: "workspace",
        tools: workspaceTools,
        knownClassifications: workspaceClassifications,
        origins: workspaceOrigins,
        crossOriginOnly: true,
      }).map(withFindingFingerprint),
    );
  }

  return findings;
}

export function mergeLayer3Findings(
  baseReport: CodeGateReport,
  layer3Findings: Finding[],
): CodeGateReport {
  return applyReportSummary({
    ...baseReport,
    findings: [...baseReport.findings, ...layer3Findings].map(withFindingFingerprint),
  });
}

export async function runDeepScanWithConsent(
  resources: DeepScanResource[],
  requestConsent: (resource: DeepScanResource) => Promise<boolean> | boolean,
  execute: (resource: DeepScanResource) => Promise<ResourceFetchResult>,
): Promise<DeepScanOutcome[]> {
  const outcomes: DeepScanOutcome[] = [];

  for (const resource of resources) {
    const approved = await requestConsent(resource);
    if (!approved) {
      outcomes.push({
        resourceId: resource.id,
        approved: false,
        status: "skipped_without_consent",
      });
      continue;
    }

    const result = await execute(resource);
    outcomes.push({
      resourceId: resource.id,
      approved: true,
      status: result.status,
      result,
    });
  }

  return outcomes;
}
