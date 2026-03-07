import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";

export interface RuleFileInput {
  filePath: string;
  textContent: string;
  unicodeAnalysis?: boolean;
}

interface FindingNarrative {
  observed?: string[];
  inference?: string;
  notVerified?: string[];
  incidentId?: string;
  incidentTitle?: string;
  incidentPrimary?: boolean;
}

const DIRECT_OVERRIDE_PHRASES = [
  "ignore previous instructions",
  "skip permissions",
  "bypass permissions",
] as const;
const NEGATION_PATTERN = /\b(?:must not|should not|do not|don't|never)\b/iu;
const SENSITIVE_READ_PATTERN =
  /\b(?:read|cat)\s+(?:~\/\.ssh(?:\/[^\s]+)?|\.env\b|~\/\.[a-z0-9._-]+(?:\/[^\s]+)*)/iu;
const OUTBOUND_TRANSFER_PATTERN =
  /\b(?:upload externally|send to (?:an |a )?(?:external )?(?:webhook|endpoint|server)|curl\b|wget\b|invoke-webrequest\b|post to\b|https?:\/\/|exfiltrat(?:e|ion|ing))\b/iu;
const SUSPICIOUS_LONG_LINE_PATTERN =
  /\b(?:ignore previous instructions|skip permissions|bypass permissions|upload externally|curl\b|wget\b|https?:\/\/|bash\s+-lc|sh\s+-c|powershell\b|base64\b|~\/\.ssh|\.env\b)\b/iu;
const REMOTE_SHELL_PATTERN =
  /\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:bash|sh)\b|\b(?:invoke-webrequest|iwr)\b[^\n|]{0,240}\|\s*(?:iex|invoke-expression)\b/iu;
const HTML_COMMENT_PATTERN = /<!--([\s\S]*?)-->/gu;
const COMMENT_PAYLOAD_PATTERN =
  /\b(?:secret instructions|ignore previous instructions|curl\b|wget\b|invoke-webrequest\b|bash\b|powershell\b|session share\b|profile sync\b)\b/iu;
const COOKIE_EXPORT_PATTERN = /\bcookies?\s+(?:export|import|get)\b/iu;
const SESSION_SHARE_PATTERN = /\bsession\s+share\b|\blive url\b/iu;
const PROFILE_SYNC_PATTERN =
  /\bprofile\s+sync\b|\breal chrome\b|\blogin sessions\b|\bsession tokens?\b|--profile\b/iu;
const BOOTSTRAP_INSTALL_PATTERN =
  /\b(?:npm|pnpm|yarn|bun)\s+install\s+-g\b|\bbrew\s+install\b|\bpipx\s+install\b|\bgo\s+install\b|\b(?:npx|pnpx|uvx)\b[^\n`]{0,160}@latest\b/iu;
const AGENT_CONTROL_POINT_PATTERN =
  /\.claude\/hooks\/|\.claude\/settings\.json|\.claude\/agents\/|\bclaude\.md\b|\bagents\.md\b|\bmcp configuration\b/iu;
const RESTART_LOAD_PATTERN =
  /\brestart\b.*\b(?:load|take effect|activate|reload|work)\b|\bonly load after restart\b|\bafter restarting\b/iu;

function makeFinding(
  filePath: string,
  field: string,
  ruleId: string,
  description: string,
  evidence?: FindingEvidence | null,
  severity: Finding["severity"] = "HIGH",
  narrative: FindingNarrative = {},
): Finding {
  const location: Finding["location"] = { field };
  if (typeof evidence?.line === "number") {
    location.line = evidence.line;
  }
  if (typeof evidence?.column === "number") {
    location.column = evidence.column;
  }

  return {
    rule_id: ruleId,
    finding_id: `RULE_INJECTION-${filePath}-${field}`,
    severity,
    category: "RULE_INJECTION",
    layer: "L2",
    file_path: filePath,
    location,
    description,
    affected_tools: [
      "claude-code",
      "codex-cli",
      "opencode",
      "cursor",
      "windsurf",
      "github-copilot",
    ],
    cve: null,
    owasp: ["ASI01"],
    cwe: "CWE-116",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["strip_unicode", "remove_block", "quarantine_file"],
    evidence: evidence?.evidence ?? null,
    observed: narrative.observed ?? null,
    inference: narrative.inference ?? null,
    not_verified: narrative.notVerified ?? null,
    incident_id: narrative.incidentId ?? null,
    incident_title: narrative.incidentTitle ?? null,
    incident_primary: narrative.incidentPrimary ?? null,
    suppressed: false,
  };
}

function buildLineEvidence(line: string, lineNumber: number, column: number): FindingEvidence {
  return {
    evidence: `line ${lineNumber}\n${lineNumber} | ${line}`,
    line: lineNumber,
    column,
  };
}

function buildMultilineEvidence(lines: string[], lineNumbers: number[]): FindingEvidence {
  const uniqueLines = Array.from(new Set(lineNumbers)).sort((left, right) => left - right);
  const snippets = uniqueLines.map(
    (lineNumber) => `${lineNumber} | ${lines[lineNumber - 1] ?? ""}`,
  );
  return {
    evidence: `lines ${uniqueLines.join(", ")}\n${snippets.join("\n")}`,
    line: uniqueLines[0] ?? 1,
    column: 1,
  };
}

function hasNearbyNegation(line: string, matchIndex: number): boolean {
  const prefix = line.slice(Math.max(0, matchIndex - 24), matchIndex);
  return NEGATION_PATTERN.test(prefix);
}

function detectSuspiciousInstruction(
  lines: string[],
): { phrase: string; evidence: FindingEvidence } | null {
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const lower = line.toLowerCase();

    for (const phrase of DIRECT_OVERRIDE_PHRASES) {
      const matchIndex = lower.indexOf(phrase);
      if (matchIndex < 0 || hasNearbyNegation(lower, matchIndex)) {
        continue;
      }
      return {
        phrase,
        evidence: buildLineEvidence(line, index + 1, matchIndex + 1),
      };
    }

    const sensitiveReadMatch = line.match(SENSITIVE_READ_PATTERN);
    const outboundMatch = line.match(OUTBOUND_TRANSFER_PATTERN);
    if (!sensitiveReadMatch || !outboundMatch) {
      continue;
    }

    const outboundIndex = outboundMatch.index ?? line.length;
    if (hasNearbyNegation(lower, outboundIndex)) {
      continue;
    }

    const phrase = outboundMatch[0].toLowerCase();
    return {
      phrase,
      evidence: buildLineEvidence(line, index + 1, outboundIndex + 1),
    };
  }

  return null;
}

function detectRemoteShell(lines: string[]): FindingEvidence | null {
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const match = line.match(REMOTE_SHELL_PATTERN);
    if (!match) {
      continue;
    }

    const matchIndex = match.index ?? 0;
    if (hasNearbyNegation(line.toLowerCase(), matchIndex)) {
      continue;
    }

    return buildLineEvidence(line, index + 1, matchIndex + 1);
  }

  return null;
}

function shellLabelFromEvidence(evidence: FindingEvidence | null): string {
  const raw = evidence?.evidence?.toLowerCase() ?? "";
  if (raw.includes("| bash")) {
    return "bash";
  }
  if (raw.includes("| sh")) {
    return "sh";
  }
  if (raw.includes("| iex") || raw.includes("| invoke-expression")) {
    return "PowerShell";
  }
  return "a shell";
}

function detectHiddenCommentPayload(input: RuleFileInput, lines: string[]): FindingEvidence | null {
  HTML_COMMENT_PATTERN.lastIndex = 0;
  let match = HTML_COMMENT_PATTERN.exec(input.textContent);
  while (match) {
    const commentBody = match[1] ?? "";
    if (!COMMENT_PAYLOAD_PATTERN.test(commentBody)) {
      match = HTML_COMMENT_PATTERN.exec(input.textContent);
      continue;
    }

    const startLine = input.textContent.slice(0, match.index ?? 0).split(/\r?\n/u).length;
    const endLine = startLine + match[0].split(/\r?\n/u).length - 1;
    const lineNumbers = Array.from(
      { length: endLine - startLine + 1 },
      (_, index) => startLine + index,
    );
    return buildMultilineEvidence(lines, lineNumbers);
  }

  return null;
}

function detectSessionTransfer(lines: string[]): FindingEvidence | null {
  const matchedLines: number[] = [];
  const categories = new Set<string>();

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const lower = line.toLowerCase();
    if (NEGATION_PATTERN.test(lower)) {
      continue;
    }

    let matched = false;
    if (COOKIE_EXPORT_PATTERN.test(line)) {
      categories.add("cookies");
      matched = true;
    }
    if (SESSION_SHARE_PATTERN.test(line)) {
      categories.add("session_share");
      matched = true;
    }
    if (PROFILE_SYNC_PATTERN.test(line)) {
      categories.add("profile");
      matched = true;
    }

    if (matched) {
      matchedLines.push(index + 1);
    }
  }

  if (categories.size < 2 || matchedLines.length < 2) {
    return null;
  }

  return buildMultilineEvidence(lines, matchedLines.slice(0, 4));
}

function detectBootstrapControlPoints(lines: string[]): FindingEvidence | null {
  const installLines: number[] = [];
  const controlPointLines: number[] = [];
  const restartLines: number[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const lineNumber = index + 1;

    if (BOOTSTRAP_INSTALL_PATTERN.test(line)) {
      installLines.push(lineNumber);
    }

    if (AGENT_CONTROL_POINT_PATTERN.test(line)) {
      controlPointLines.push(lineNumber);
    }

    if (RESTART_LOAD_PATTERN.test(line)) {
      restartLines.push(lineNumber);
    }
  }

  if (installLines.length === 0 || controlPointLines.length === 0 || restartLines.length === 0) {
    return null;
  }

  return buildMultilineEvidence(lines, [
    ...installLines.slice(0, 2),
    ...controlPointLines.slice(0, 2),
    restartLines[0],
  ]);
}

export function detectRuleFileIssues(input: RuleFileInput): Finding[] {
  const findings: Finding[] = [];
  const hiddenUnicodeRegex = /(?:\u200B|\u200C|\u200D|\u2060|\uFEFF|[\u202A-\u202E])/u;
  const hiddenRemoteShellIncident: FindingNarrative = {
    incidentId: "hidden-remote-shell-payload",
    incidentTitle: "Hidden remote shell payload in skill file",
  };

  const hiddenMatch =
    input.unicodeAnalysis === false ? null : input.textContent.match(hiddenUnicodeRegex);
  if (hiddenMatch?.[0]) {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [hiddenMatch[0]],
      fallbackValue: "hidden Unicode character detected",
    });
    findings.push(
      makeFinding(
        input.filePath,
        "hidden_unicode",
        "rule-file-hidden-unicode",
        "Rule file contains hidden Unicode characters",
        evidence,
      ),
    );
  }

  const lines = input.textContent.split(/\r?\n/u);
  const hiddenCommentPayload = detectHiddenCommentPayload(input, lines);
  if (hiddenCommentPayload) {
    findings.push(
      makeFinding(
        input.filePath,
        "hidden_comment_payload",
        "rule-file-hidden-comment-payload",
        "Rule file contains a hidden comment payload with executable or override instructions",
        hiddenCommentPayload,
        "CRITICAL",
        {
          ...hiddenRemoteShellIncident,
          incidentPrimary: true,
          observed: [
            "A hidden HTML comment block contains agent-directed instructions.",
            "The hidden block includes a secret instruction directive aimed at the agent.",
          ],
          inference:
            "The skill conceals instructions from the human reader while attempting to steer agent behavior.",
          notVerified: [
            "CodeGate did not execute any instruction from the hidden block.",
            "CodeGate did not fetch or inspect any referenced remote content.",
          ],
        },
      ),
    );
  }

  const suspiciousInstruction = detectSuspiciousInstruction(lines);
  if (suspiciousInstruction) {
    findings.push(
      makeFinding(
        input.filePath,
        "suspicious_instruction",
        "rule-file-suspicious-instruction",
        `Rule file contains suspicious instruction pattern: ${suspiciousInstruction.phrase}`,
        suspiciousInstruction.evidence,
      ),
    );
  }

  const remoteShell = detectRemoteShell(lines);
  if (remoteShell) {
    const remoteShellNarrative: FindingNarrative = {
      observed: [
        "The file instructs the agent to download remote content with curl.",
        `The downloaded content is piped directly into ${shellLabelFromEvidence(remoteShell)}.`,
      ],
      inference:
        "Following this instruction would execute remote code supplied by the referenced URL.",
      notVerified: [
        "CodeGate did not fetch the referenced URL.",
        "CodeGate did not execute the piped shell command.",
      ],
      ...(hiddenCommentPayload ? hiddenRemoteShellIncident : {}),
    };
    findings.push(
      makeFinding(
        input.filePath,
        "remote_shell",
        "rule-file-remote-shell",
        "Rule file instructs fetching remote content and piping it into a shell",
        remoteShell,
        "CRITICAL",
        remoteShellNarrative,
      ),
    );
  }

  const sessionTransfer = detectSessionTransfer(lines);
  if (sessionTransfer) {
    findings.push(
      makeFinding(
        input.filePath,
        "session_transfer",
        "rule-file-session-transfer",
        "Rule file describes transferring authenticated browser cookies, profiles, or shared sessions",
        sessionTransfer,
        "HIGH",
      ),
    );
  }

  const bootstrapControlPoints = detectBootstrapControlPoints(lines);
  if (bootstrapControlPoints) {
    findings.push(
      makeFinding(
        input.filePath,
        "bootstrap_control_points",
        "rule-file-bootstrap-control-points",
        "Rule file bootstraps persistent agent hooks or settings and requires restart to activate them",
        bootstrapControlPoints,
        "HIGH",
        {
          incidentId: "bootstrap-control-points",
          incidentTitle: "Persistent agent bootstrap via hooks and settings",
          incidentPrimary: true,
          observed: [
            "The file instructs installing or bootstrapping tooling with global or latest-version commands.",
            "The bootstrap flow writes persistent agent control points such as hooks, settings, or agent instructions.",
            "The file states that a restart is required for the new control points to take effect.",
          ],
          inference:
            "Following this skill would create persistent agent behavior changes that survive the current task and expand future execution control.",
          notVerified: [
            "CodeGate did not run the bootstrap or installer commands.",
            "CodeGate did not modify any local hooks, settings, or agent instruction files.",
          ],
        },
      ),
    );
  }

  const longLineIndex = lines.findIndex(
    (line) =>
      line.length > 300 && SUSPICIOUS_LONG_LINE_PATTERN.test(line) && !NEGATION_PATTERN.test(line),
  );
  if (longLineIndex >= 0) {
    const lineNumber = longLineIndex + 1;
    const evidence: FindingEvidence = {
      evidence: `line ${lineNumber}\n${lineNumber} | ${lines[longLineIndex]}`,
      line: lineNumber,
      column: 1,
    };
    findings.push(
      makeFinding(
        input.filePath,
        "long_line",
        "rule-file-long-line",
        "Rule file contains unusually long lines that may hide payloads",
        evidence,
      ),
    );
  }

  return findings;
}
