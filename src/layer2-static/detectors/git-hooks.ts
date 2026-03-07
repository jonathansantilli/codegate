import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";

export interface GitHookEntry {
  path: string;
  content: string;
  executable: boolean;
}

export interface GitHooksInput {
  hooks: GitHookEntry[];
  knownSafeHooks?: string[];
}

function makeFinding(path: string, description: string, evidence?: FindingEvidence | null): Finding {
  const location: Finding["location"] = { field: "hook_content" };
  if (typeof evidence?.line === "number") {
    location.line = evidence.line;
  }
  if (typeof evidence?.column === "number") {
    location.column = evidence.column;
  }

  return {
    rule_id: "git-hook-suspicious-pattern",
    finding_id: `GIT_HOOK-${path}`,
    severity: "MEDIUM",
    category: "GIT_HOOK",
    layer: "L2",
    file_path: path,
    location,
    description,
    affected_tools: ["claude-code", "codex-cli", "opencode", "cursor", "windsurf", "github-copilot"],
    cve: null,
    owasp: ["ASI05", "ASI06"],
    cwe: "CWE-78",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_execute_permission", "quarantine_file", "remove_file"],
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

export function detectGitHookIssues(input: GitHooksInput): Finding[] {
  const findings: Finding[] = [];
  const knownSafeHooks = new Set((input.knownSafeHooks ?? []).map((hook) => hook.trim()).filter((hook) => hook.length > 0));
  const suspiciousPattern = /\b(curl|wget|nc|ncat|socat)\b|[|;&`]|[$][(]/u;
  const exfilPattern = /(~\/\.ssh|~\/\.aws|\.env|id_rsa|git-credentials)/u;

  for (const hook of input.hooks) {
    if (knownSafeHooks.has(hook.path)) {
      continue;
    }
    if (!hook.executable) {
      continue;
    }
    if (suspiciousPattern.test(hook.content) || exfilPattern.test(hook.content)) {
      const suspiciousMatch = hook.content.match(suspiciousPattern)?.[0];
      const exfilMatch = hook.content.match(exfilPattern)?.[0];
      const evidence = buildFindingEvidence({
        textContent: hook.content,
        searchTerms: [suspiciousMatch ?? "", exfilMatch ?? ""],
        fallbackValue: "suspicious hook content detected",
      });
      findings.push(
        makeFinding(hook.path, "Executable hook contains suspicious command or exfiltration pattern", evidence),
      );
    }
  }

  return findings;
}
