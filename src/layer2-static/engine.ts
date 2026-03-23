import { detectCommandExecution } from "./detectors/command-exec.js";
import { detectAdvisoryIntelligence } from "./detectors/advisory-intelligence.js";
import { detectConsentBypass } from "./detectors/consent-bypass.js";
import { detectEnvOverrides } from "./detectors/env-override.js";
import { detectGitHookIssues, type GitHookEntry } from "./detectors/git-hooks.js";
import { detectIdeSettingsIssues } from "./detectors/ide-settings.js";
import { detectPluginManifestIssues } from "./detectors/plugin-manifest.js";
import { detectRuleFileIssues } from "./detectors/rule-file.js";
import { detectSymlinkEscapes, type SymlinkEscapeEntry } from "./detectors/symlink.js";
import { detectWorkflowExcessivePermissions } from "./detectors/workflow-excessive-permissions.js";
import { detectWorkflowDangerousTriggers } from "./detectors/workflow-dangerous-triggers.js";
import { detectWorkflowTemplateInjection } from "./detectors/workflow-template-injection.js";
import { detectWorkflowKnownVulnAction } from "./detectors/workflow-known-vuln-action.js";
import { detectWorkflowUnpinnedUses } from "./detectors/workflow-unpinned-uses.js";
import { detectWorkflowArtipacked } from "./detectors/workflow-artipacked.js";
import { detectWorkflowCachePoisoning } from "./detectors/workflow-cache-poisoning.js";
import { detectWorkflowGithubEnv } from "./detectors/workflow-github-env.js";
import { detectWorkflowRunUntrustedArtifact } from "./detectors/workflow-run-untrusted-artifact.js";
import { detectWorkflowInsecureCommands } from "./detectors/workflow-insecure-commands.js";
import { detectWorkflowSelfHostedRunner } from "./detectors/workflow-self-hosted-runner.js";
import { detectWorkflowOverprovisionedSecrets } from "./detectors/workflow-overprovisioned-secrets.js";
import { detectWorkflowSecretsOutsideEnv } from "./detectors/workflow-secrets-outside-env.js";
import { detectWorkflowSecretsInherit } from "./detectors/workflow-secrets-inherit.js";
import { detectWorkflowUndocumentedPermissions } from "./detectors/workflow-undocumented-permissions.js";
import { detectWorkflowUseTrustedPublishing } from "./detectors/workflow-use-trusted-publishing.js";
import { detectWorkflowArchivedUses } from "./detectors/workflow-archived-uses.js";
import { detectWorkflowStaleActionRefs } from "./detectors/workflow-stale-action-refs.js";
import { detectWorkflowForbiddenUses } from "./detectors/workflow-forbidden-uses.js";
import { detectWorkflowRefConfusion } from "./detectors/workflow-ref-confusion.js";
import { detectWorkflowRefVersionMismatch } from "./detectors/workflow-ref-version-mismatch.js";
import { detectWorkflowImpostorCommit } from "./detectors/workflow-impostor-commit.js";
import { detectWorkflowUnsafeCheckoutRef } from "./detectors/workflow-unsafe-checkout-ref.js";
import { detectWorkflowUnpinnedImages } from "./detectors/workflow-unpinned-images.js";
import { detectWorkflowFloatingActionVersion } from "./detectors/workflow-floating-action-version.js";
import { detectWorkflowAnonymousDefinition } from "./detectors/workflow-anonymous-definition.js";
import { detectWorkflowConcurrencyLimits } from "./detectors/workflow-concurrency-limits.js";
import { detectWorkflowSuperfluousActions } from "./detectors/workflow-superfluous-actions.js";
import { detectWorkflowMisfeature } from "./detectors/workflow-misfeature.js";
import { detectWorkflowObfuscation } from "./detectors/workflow-obfuscation.js";
import { detectWorkflowUnsoundCondition } from "./detectors/workflow-unsound-condition.js";
import { detectWorkflowUnsoundContains } from "./detectors/workflow-unsound-contains.js";
import { detectDependabotCooldown } from "./detectors/dependabot-cooldown.js";
import { detectDependabotExecution } from "./detectors/dependabot-execution.js";
import { detectWorkflowHardcodedContainerCredentials } from "./detectors/workflow-hardcoded-container-credentials.js";
import { detectWorkflowUnredactedSecrets } from "./detectors/workflow-unredacted-secrets.js";
import { detectWorkflowBotConditions } from "./detectors/workflow-bot-conditions.js";
import { detectWorkflowPrTargetCheckoutHead } from "./detectors/workflow-pr-target-checkout-head.js";
import { detectWorkflowArtifactTrustChain } from "./detectors/workflow-artifact-trust-chain.js";
import { detectWorkflowCallBoundary } from "./detectors/workflow-call-boundary.js";
import { detectWorkflowSecretExfiltration } from "./detectors/workflow-secret-exfiltration.js";
import { detectWorkflowOidcUntrustedContext } from "./detectors/workflow-oidc-untrusted-context.js";
import { detectWorkflowDynamicMatrixInjection } from "./detectors/workflow-dynamic-matrix-injection.js";
import { detectDependabotAutoMerge } from "./detectors/dependabot-auto-merge.js";
import { detectWorkflowLocalActionMutation } from "./detectors/workflow-local-action-mutation.js";
import { filterRegisteredAudits, type RegisteredAudit } from "./audits/registry.js";
import type { AuditPersona, RuntimeMode } from "../config.js";
import { FINDING_CATEGORIES, type Finding } from "../types/finding.js";
import type { DiscoveryFormat } from "../types/discovery.js";
import { buildFindingEvidence } from "./evidence.js";
import { evaluateRule, loadRulePacks, type DetectionRule } from "./rule-engine.js";

export interface StaticFileInput {
  filePath: string;
  format: DiscoveryFormat;
  parsed: unknown;
  textContent: string;
}

export interface StaticEngineConfig {
  knownSafeMcpServers: string[];
  knownSafeFormatters: string[];
  knownSafeLspServers: string[];
  knownSafeHooks: string[];
  blockedCommands: string[];
  trustedApiDomains: string[];
  unicodeAnalysis: boolean;
  checkIdeSettings: boolean;
  rulePackPaths?: string[];
  allowedRules?: string[];
  skipRules?: string[];
  persona?: AuditPersona;
  runtimeMode?: RuntimeMode;
  workflowAuditsEnabled?: boolean;
  rulePolicies?: Record<string, { disable?: boolean; config?: Record<string, unknown> }>;
}

export interface StaticEngineInput {
  projectRoot: string;
  files: StaticFileInput[];
  symlinkEscapes: SymlinkEscapeEntry[];
  hooks: GitHookEntry[];
  config: StaticEngineConfig;
}

const GENERIC_AFFECTED_TOOLS = [
  "claude-code",
  "codex-cli",
  "opencode",
  "cursor",
  "windsurf",
  "github-copilot",
];

interface FileAuditContext {
  file: StaticFileInput;
  input: StaticEngineInput;
}

interface GlobalAuditContext {
  input: StaticEngineInput;
}

function parseRuleSeverity(value: string): Finding["severity"] {
  const normalized = value.trim().toUpperCase();
  if (
    normalized === "CRITICAL" ||
    normalized === "HIGH" ||
    normalized === "MEDIUM" ||
    normalized === "LOW"
  ) {
    return normalized;
  }
  return "INFO";
}

function parseRuleCategory(value: string): Finding["category"] {
  const normalized = value.trim().toUpperCase();
  if (FINDING_CATEGORIES.some((category) => category === normalized)) {
    return normalized as Finding["category"];
  }
  return "CONFIG_PRESENT";
}

function remediationActionsForRule(rule: DetectionRule): string[] {
  if (rule.query_type === "text_pattern") {
    return ["quarantine_file", "remove_block"];
  }
  return ["remove_field", "replace_with_default"];
}

function resolveDisabledAuditIds(
  policies: StaticEngineConfig["rulePolicies"] | undefined,
): string[] {
  if (!policies) {
    return [];
  }

  return Object.entries(policies)
    .filter(([, policy]) => policy?.disable === true)
    .map(([ruleId]) => ruleId);
}

function findRulePolicyConfig(
  policies: StaticEngineConfig["rulePolicies"] | undefined,
  ruleId: string,
): Record<string, unknown> | undefined {
  const config = policies?.[ruleId]?.config;
  return config && typeof config === "object" ? config : undefined;
}

function findingFromRulePackMatch(file: StaticFileInput, rule: DetectionRule): Finding {
  const locationField = rule.query_type === "text_pattern" ? "content" : rule.query;
  const evidence = buildFindingEvidence({
    textContent: file.textContent,
    searchTerms: [rule.query],
    fallbackValue: `${locationField} matched rule ${rule.id}`,
  });
  const affectedTools = rule.tool === "*" ? GENERIC_AFFECTED_TOOLS : [rule.tool];

  return {
    rule_id: rule.id,
    finding_id: `RULE_PACK-${rule.id}-${file.filePath}-${locationField}`,
    severity: parseRuleSeverity(rule.severity),
    category: parseRuleCategory(rule.category),
    layer: "L2",
    file_path: file.filePath,
    location: { field: locationField },
    description: rule.description,
    affected_tools: affectedTools,
    cve: rule.cve ?? null,
    owasp: rule.owasp,
    cwe: rule.cwe,
    confidence: "HIGH",
    fixable: true,
    remediation_actions: remediationActionsForRule(rule),
    metadata: {
      sources: [file.filePath, locationField],
      risk_tags: ["rule-pack"],
      origin: "rule-pack",
    },
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

function hasEquivalentFinding(findings: Finding[], candidate: Finding): boolean {
  return findings.some(
    (finding) =>
      finding.rule_id === candidate.rule_id &&
      finding.file_path === candidate.file_path &&
      (finding.location.field ?? "") === (candidate.location.field ?? ""),
  );
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const deduped = new Map<string, Finding>();

  for (const finding of findings) {
    const key = `${finding.category}:${finding.rule_id}:${finding.description}`;
    const existing = deduped.get(key);

    if (!existing) {
      deduped.set(key, {
        ...finding,
        affected_locations: [{ file_path: finding.file_path, location: finding.location }],
      });
      continue;
    }

    const nextLocation = { file_path: finding.file_path, location: finding.location };
    const locations = existing.affected_locations ?? [];
    const alreadyIncluded = locations.some(
      (location) =>
        location.file_path === nextLocation.file_path &&
        location.location?.field === nextLocation.location?.field &&
        location.location?.line === nextLocation.location?.line,
    );
    if (!alreadyIncluded) {
      locations.push(nextLocation);
    }
    existing.affected_locations = locations;
  }

  return Array.from(deduped.values());
}

function buildFileAudits(): Array<RegisteredAudit<FileAuditContext>> {
  return [
    {
      id: "env-overrides",
      run: ({ file, input }) =>
        detectEnvOverrides({
          filePath: file.filePath,
          parsed: file.parsed,
          textContent: file.textContent,
          trustedApiDomains: input.config.trustedApiDomains,
        }),
    },
    {
      id: "consent-bypass",
      run: ({ file, input }) =>
        detectConsentBypass({
          filePath: file.filePath,
          parsed: file.parsed,
          textContent: file.textContent,
          trustedApiDomains: input.config.trustedApiDomains,
        }),
    },
    {
      id: "command-execution",
      run: ({ file, input }) =>
        detectCommandExecution({
          filePath: file.filePath,
          parsed: file.parsed,
          textContent: file.textContent,
          knownSafeMcpServers: input.config.knownSafeMcpServers,
          knownSafeFormatters: input.config.knownSafeFormatters,
          knownSafeLspServers: input.config.knownSafeLspServers,
          blockedCommands: input.config.blockedCommands,
        }),
    },
    {
      id: "ide-settings",
      run: ({ file, input }) =>
        input.config.checkIdeSettings
          ? detectIdeSettingsIssues({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
              projectRoot: input.projectRoot,
            })
          : [],
    },
    {
      id: "plugin-manifest",
      run: ({ file, input }) =>
        detectPluginManifestIssues({
          filePath: file.filePath,
          parsed: file.parsed,
          textContent: file.textContent,
          trustedApiDomains: input.config.trustedApiDomains,
          blockedCommands: input.config.blockedCommands,
        }),
    },
    {
      id: "advisory-intelligence",
      run: ({ file }) =>
        detectAdvisoryIntelligence({
          filePath: file.filePath,
          parsed: file.parsed,
          textContent: file.textContent,
        }),
    },
    {
      id: "rule-file",
      run: ({ file, input }) =>
        file.format === "text" || file.format === "markdown"
          ? detectRuleFileIssues({
              filePath: file.filePath,
              textContent: file.textContent,
              unicodeAnalysis: input.config.unicodeAnalysis,
            })
          : [],
    },
    {
      id: "workflow-unpinned-uses",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowUnpinnedUses({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-dangerous-triggers",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowDangerousTriggers({
              filePath: file.filePath,
              parsed: file.parsed,
            })
          : [],
    },
    {
      id: "workflow-excessive-permissions",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowExcessivePermissions({
              filePath: file.filePath,
              parsed: file.parsed,
            })
          : [],
    },
    {
      id: "workflow-template-injection",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowTemplateInjection({
              filePath: file.filePath,
              parsed: file.parsed,
            })
          : [],
    },
    {
      id: "workflow-known-vuln-action",
      onlineRequired: true,
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowKnownVulnAction({
              filePath: file.filePath,
              parsed: file.parsed,
              runtimeMode: input.config.runtimeMode,
            })
          : [],
    },
    {
      id: "workflow-artipacked",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowArtipacked({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-cache-poisoning",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowCachePoisoning({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-github-env",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowGithubEnv({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-run-untrusted-artifact",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowRunUntrustedArtifact({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-insecure-commands",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowInsecureCommands({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-self-hosted-runner",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowSelfHostedRunner({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-overprovisioned-secrets",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowOverprovisionedSecrets({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-secrets-outside-env",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowSecretsOutsideEnv({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-secrets-inherit",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowSecretsInherit({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-undocumented-permissions",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowUndocumentedPermissions({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-use-trusted-publishing",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowUseTrustedPublishing({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-archived-uses",
      onlineRequired: true,
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowArchivedUses({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-stale-action-refs",
      onlineRequired: true,
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowStaleActionRefs({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-forbidden-uses",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowForbiddenUses({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
              config: findRulePolicyConfig(input.config.rulePolicies, "workflow-forbidden-uses"),
            })
          : [],
    },
    {
      id: "workflow-ref-confusion",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowRefConfusion({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-ref-version-mismatch",
      onlineRequired: true,
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowRefVersionMismatch({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
              runtimeMode: input.config.runtimeMode,
            })
          : [],
    },
    {
      id: "workflow-unsafe-checkout-ref",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowUnsafeCheckoutRef({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-floating-action-version",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowFloatingActionVersion({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-impostor-commit",
      onlineRequired: true,
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowImpostorCommit({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
              runtimeMode: input.config.runtimeMode,
            })
          : [],
    },
    {
      id: "workflow-unpinned-images",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowUnpinnedImages({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-anonymous-definition",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowAnonymousDefinition({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-concurrency-limits",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowConcurrencyLimits({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-superfluous-actions",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowSuperfluousActions({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-misfeature",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowMisfeature({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-obfuscation",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowObfuscation({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-unsound-condition",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowUnsoundCondition({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-unsound-contains",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowUnsoundContains({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "dependabot-cooldown",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectDependabotCooldown({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "dependabot-execution",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectDependabotExecution({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-pr-target-checkout-head",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowPrTargetCheckoutHead({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-artifact-trust-chain",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowArtifactTrustChain({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-call-boundary",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowCallBoundary({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-secret-exfiltration",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowSecretExfiltration({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
              trustedApiDomains: input.config.trustedApiDomains,
            })
          : [],
    },
    {
      id: "workflow-oidc-untrusted-context",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowOidcUntrustedContext({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-dynamic-matrix-injection",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowDynamicMatrixInjection({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "dependabot-auto-merge",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectDependabotAutoMerge({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "workflow-local-action-mutation",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowLocalActionMutation({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "hardcoded-container-credentials",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowHardcodedContainerCredentials({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "unredacted-secrets",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowUnredactedSecrets({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
    {
      id: "bot-conditions",
      run: ({ file, input }) =>
        input.config.workflowAuditsEnabled
          ? detectWorkflowBotConditions({
              filePath: file.filePath,
              parsed: file.parsed,
              textContent: file.textContent,
            })
          : [],
    },
  ];
}

function buildGlobalAudits(): Array<RegisteredAudit<GlobalAuditContext>> {
  return [
    {
      id: "symlink-escapes",
      run: ({ input }) => detectSymlinkEscapes({ symlinkEscapes: input.symlinkEscapes }),
    },
    {
      id: "git-hooks",
      run: ({ input }) =>
        detectGitHookIssues({ hooks: input.hooks, knownSafeHooks: input.config.knownSafeHooks }),
    },
  ];
}

export async function runStaticEngine(input: StaticEngineInput): Promise<Finding[]> {
  const findings: Finding[] = [];
  const runtimeSelection = {
    persona: input.config.persona,
    runtimeMode: input.config.runtimeMode,
    disabledAuditIds: resolveDisabledAuditIds(input.config.rulePolicies),
  };
  const activeFileAudits = filterRegisteredAudits(buildFileAudits(), runtimeSelection);
  const activeGlobalAudits = filterRegisteredAudits(buildGlobalAudits(), runtimeSelection);
  const rulePackRules = loadRulePacks({
    rule_pack_paths: input.config.rulePackPaths ?? [],
    allowed_rules: input.config.allowedRules ?? [],
    skip_rules: input.config.skipRules ?? [],
  });

  for (const file of input.files) {
    for (const audit of activeFileAudits) {
      findings.push(...(await audit.run({ file, input })));
    }

    for (const rule of rulePackRules) {
      if (
        !evaluateRule(rule, {
          filePath: file.filePath,
          format: file.format,
          parsed: file.parsed,
          textContent: file.textContent,
        })
      ) {
        continue;
      }

      const candidate = findingFromRulePackMatch(file, rule);
      if (!hasEquivalentFinding(findings, candidate)) {
        findings.push(candidate);
      }
    }
  }

  for (const audit of activeGlobalAudits) {
    findings.push(...(await audit.run({ input })));
  }

  return dedupeFindings(findings);
}
