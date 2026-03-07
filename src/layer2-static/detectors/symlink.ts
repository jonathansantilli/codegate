import type { Finding } from "../../types/finding.js";

export interface SymlinkEscapeEntry {
  path: string;
  target: string;
}

export interface SymlinkInput {
  symlinkEscapes: SymlinkEscapeEntry[];
}

function makeFinding(path: string, target: string, severity: Finding["severity"]): Finding {
  return {
    rule_id: "symlink-escape",
    finding_id: `SYMLINK_ESCAPE-${path}`,
    severity,
    category: "SYMLINK_ESCAPE",
    layer: "L2",
    file_path: path,
    location: { field: "symlink_target" },
    description: `Symlink resolves outside project root: ${target}`,
    affected_tools: ["claude-code", "codex-cli", "opencode", "cursor", "windsurf", "github-copilot"],
    cve: null,
    owasp: ["ASI06"],
    cwe: "CWE-59",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_symlink", "quarantine_file"],
    suppressed: false,
  };
}

export function detectSymlinkEscapes(input: SymlinkInput): Finding[] {
  const sensitiveIndicators = [
    "/.ssh/",
    "/.aws/",
    "/.kube/",
    "/.docker/",
    "/.npmrc",
    "/.git-credentials",
    "/etc/passwd",
    "/etc/shadow",
  ];

  return input.symlinkEscapes.map((entry) => {
    const severity = sensitiveIndicators.some((token) => entry.target.includes(token))
      ? "HIGH"
      : "MEDIUM";
    return makeFinding(entry.path, entry.target, severity);
  });
}
