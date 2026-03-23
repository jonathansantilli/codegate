import { buildFindingEvidence } from "../evidence.js";
import type { Finding } from "../../types/finding.js";
import { extractDependabotFacts, isGitHubDependabotPath } from "../dependabot/parser.js";

export interface DependabotCooldownInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
}

function hasCooldown(update: {
  cooldown?: {
    defaultDays?: number;
    semverMajorDays?: number;
    semverMinorDays?: number;
    semverPatchDays?: number;
  };
}): boolean {
  const cooldown = update.cooldown;
  if (!cooldown) {
    return false;
  }

  return (
    typeof cooldown.defaultDays === "number" ||
    typeof cooldown.semverMajorDays === "number" ||
    typeof cooldown.semverMinorDays === "number" ||
    typeof cooldown.semverPatchDays === "number"
  );
}

export function detectDependabotCooldown(input: DependabotCooldownInput): Finding[] {
  if (!isGitHubDependabotPath(input.filePath)) {
    return [];
  }

  const facts = extractDependabotFacts(input.parsed);
  if (!facts || facts.updates.length === 0) {
    return [];
  }

  const findings: Finding[] = [];

  facts.updates.forEach((update, index) => {
    if (!update.schedule || hasCooldown(update)) {
      return;
    }

    const ecosystem = update.packageEcosystem ?? "unknown-ecosystem";
    const directory = update.directory ?? "/";
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [ecosystem, directory, "schedule", "cooldown"],
      fallbackValue: `${ecosystem} ${directory} update rule has no cooldown`,
    });

    findings.push({
      rule_id: "dependabot-cooldown",
      finding_id: `DEPENDABOT_COOLDOWN-${input.filePath}-${index}`,
      severity: "LOW",
      category: "CI_SUPPLY_CHAIN",
      layer: "L2",
      file_path: input.filePath,
      location: { field: `updates[${index}].cooldown` },
      description:
        "Dependabot update rule has no cooldown window, increasing update churn and review pressure",
      affected_tools: ["dependabot"],
      cve: null,
      owasp: ["ASI02"],
      cwe: "CWE-400",
      confidence: "MEDIUM",
      fixable: false,
      remediation_actions: ["Add cooldown settings to pace update volume and review load"],
      evidence: evidence?.evidence ?? null,
      suppressed: false,
    });
  });

  return findings;
}
