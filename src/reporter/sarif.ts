import type { Finding } from "../types/finding.js";
import type { CodeGateReport } from "../types/report.js";

interface SarifArtifactLocation {
  uri: string;
}

interface SarifRegion {
  startLine?: number;
  startColumn?: number;
}

interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  properties: {
    category: string;
    layer: string;
  };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: SarifLocation[];
  properties: Record<string, unknown>;
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      semanticVersion: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifReport {
  version: "2.1.0";
  $schema: string;
  runs: SarifRun[];
}

function toSarifLevel(severity: Finding["severity"]): SarifResult["level"] {
  if (severity === "CRITICAL" || severity === "HIGH") {
    return "error";
  }
  if (severity === "MEDIUM") {
    return "warning";
  }
  return "note";
}

function findingToLocation(finding: Finding): SarifLocation {
  const region: SarifRegion = {};

  if (typeof finding.location.line === "number") {
    region.startLine = finding.location.line;
  }
  if (typeof finding.location.column === "number") {
    region.startColumn = finding.location.column;
  }

  return {
    physicalLocation: {
      artifactLocation: {
        uri: finding.file_path,
      },
      region: Object.keys(region).length > 0 ? region : undefined,
    },
  };
}

function buildRules(findings: Finding[]): SarifRule[] {
  const byRuleId = new Map<string, SarifRule>();

  for (const finding of findings) {
    if (byRuleId.has(finding.rule_id)) {
      continue;
    }
    byRuleId.set(finding.rule_id, {
      id: finding.rule_id,
      shortDescription: { text: finding.description },
      properties: {
        category: finding.category,
        layer: finding.layer,
      },
    });
  }

  return Array.from(byRuleId.values());
}

function findingToResult(finding: Finding): SarifResult {
  return {
    ruleId: finding.rule_id,
    level: toSarifLevel(finding.severity),
    message: { text: finding.description },
    locations: [findingToLocation(finding)],
    properties: {
      finding_id: finding.finding_id,
      severity: finding.severity,
      category: finding.category,
      layer: finding.layer,
      confidence: finding.confidence,
      cve: finding.cve,
      owasp: finding.owasp,
      cwe: finding.cwe,
      evidence: finding.evidence ?? null,
      fixable: finding.fixable,
      suppressed: finding.suppressed,
      source_config: finding.source_config ?? null,
    },
  };
}

export function renderSarifReport(report: CodeGateReport): string {
  const sarif: SarifReport = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "CodeGate",
            semanticVersion: report.version,
            rules: buildRules(report.findings),
          },
        },
        results: report.findings.map(findingToResult),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
