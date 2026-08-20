import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";
import { scanEncodedPayloads, type EncodedPayloadMatch } from "../text/encoded-payloads.js";
import { normalizeForMatching } from "../text/normalize.js";
import {
  AGENT_CONTROL_POINT_PATTERN,
  BOOTSTRAP_INSTALL_PATTERN,
  COMMENT_PAYLOAD_PATTERN,
  COOKIE_EXPORT_PATTERN,
  HTML_COMMENT_PATTERN,
  NEGATION_PATTERN,
  OUTBOUND_TRANSFER_PATTERN,
  PROFILE_SYNC_PATTERN,
  REMOTE_INSTRUCTION_INDIRECTION_PATTERN,
  REMOTE_SHELL_PATTERN,
  RESTART_LOAD_PATTERN,
  SENSITIVE_READ_PATTERN,
  SESSION_SHARE_PATTERN,
  SUSPICIOUS_LONG_LINE_PATTERN,
  findOverridePhrase,
  hasNegationBefore,
} from "../text/threat-patterns.js";
import { HIDDEN_UNICODE_CLASS, findHiddenUnicode } from "../text/unicode.js";

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

interface NormalizedLines {
  original: string[];
  normalized: string[];
}

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
    metadata: {
      sources: [filePath, field],
      risk_tags: ["rule-injection", "prompt-injection"],
      origin: "rule-file",
    },
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

function detectSuspiciousInstruction(
  lines: NormalizedLines,
): { phrase: string; evidence: FindingEvidence } | null {
  for (let index = 0; index < lines.normalized.length; index += 1) {
    const normalized = lines.normalized[index] ?? "";
    const original = lines.original[index] ?? "";

    const overrideMatch = findOverridePhrase(normalized);
    if (overrideMatch) {
      return {
        phrase: overrideMatch.phrase,
        evidence: buildLineEvidence(original, index + 1, overrideMatch.index + 1),
      };
    }

    const sensitiveReadMatch = normalized.match(SENSITIVE_READ_PATTERN);
    const outboundMatch = normalized.match(OUTBOUND_TRANSFER_PATTERN);
    if (!sensitiveReadMatch || !outboundMatch) {
      continue;
    }

    const outboundIndex = outboundMatch.index ?? normalized.length;
    if (hasNegationBefore(normalized, outboundIndex)) {
      continue;
    }

    return {
      phrase: outboundMatch[0].toLowerCase(),
      evidence: buildLineEvidence(original, index + 1, outboundIndex + 1),
    };
  }

  return null;
}

function detectRemoteShell(lines: NormalizedLines): FindingEvidence | null {
  for (let index = 0; index < lines.normalized.length; index += 1) {
    const normalized = lines.normalized[index] ?? "";
    const match = normalized.match(REMOTE_SHELL_PATTERN);
    if (!match) {
      continue;
    }

    const matchIndex = match.index ?? 0;
    if (hasNegationBefore(normalized, matchIndex)) {
      continue;
    }

    return buildLineEvidence(lines.original[index] ?? "", index + 1, matchIndex + 1);
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
  const commentRegex = new RegExp(HTML_COMMENT_PATTERN.source, "gu");
  let match = commentRegex.exec(input.textContent);
  while (match) {
    const commentBody = normalizeForMatching(match[1] ?? "");
    if (!COMMENT_PAYLOAD_PATTERN.test(commentBody)) {
      match = commentRegex.exec(input.textContent);
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

function detectSessionTransfer(lines: NormalizedLines): FindingEvidence | null {
  const matchedLines: number[] = [];
  const categories = new Set<string>();

  for (let index = 0; index < lines.normalized.length; index += 1) {
    const normalized = lines.normalized[index] ?? "";
    if (NEGATION_PATTERN.test(normalized)) {
      continue;
    }

    let matched = false;
    if (COOKIE_EXPORT_PATTERN.test(normalized)) {
      categories.add("cookies");
      matched = true;
    }
    if (SESSION_SHARE_PATTERN.test(normalized)) {
      categories.add("session_share");
      matched = true;
    }
    if (PROFILE_SYNC_PATTERN.test(normalized)) {
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

  return buildMultilineEvidence(lines.original, matchedLines.slice(0, 4));
}

function detectBootstrapControlPoints(lines: NormalizedLines): FindingEvidence | null {
  const installLines: number[] = [];
  const controlPointLines: number[] = [];
  const restartLines: number[] = [];

  for (let index = 0; index < lines.normalized.length; index += 1) {
    const normalized = lines.normalized[index] ?? "";
    const lineNumber = index + 1;

    if (BOOTSTRAP_INSTALL_PATTERN.test(normalized)) {
      installLines.push(lineNumber);
    }

    if (AGENT_CONTROL_POINT_PATTERN.test(normalized)) {
      controlPointLines.push(lineNumber);
    }

    if (RESTART_LOAD_PATTERN.test(normalized)) {
      restartLines.push(lineNumber);
    }
  }

  if (installLines.length === 0 || controlPointLines.length === 0 || restartLines.length === 0) {
    return null;
  }

  return buildMultilineEvidence(lines.original, [
    ...installLines.slice(0, 2),
    ...controlPointLines.slice(0, 2),
    restartLines[0],
  ]);
}

function hiddenUnicodeFindings(input: RuleFileInput): Finding[] {
  if (input.unicodeAnalysis === false) {
    return [];
  }

  const matches = findHiddenUnicode(input.textContent);
  if (matches.length === 0) {
    return [];
  }

  const findings: Finding[] = [];
  const tagMatches = matches.filter((match) => match.class === HIDDEN_UNICODE_CLASS.Tags);
  const otherMatches = matches.filter((match) => match.class !== HIDDEN_UNICODE_CLASS.Tags);

  if (otherMatches.length > 0) {
    const firstChar = String.fromCodePoint(otherMatches[0]?.codePoint ?? 0x200b);
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      searchTerms: [firstChar],
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

  if (tagMatches.length > 0) {
    const lineNumber = input.textContent.slice(0, tagMatches[0]?.index ?? 0).split(/\r?\n/u).length;
    findings.push(
      makeFinding(
        input.filePath,
        "hidden_unicode_tags",
        "rule-file-hidden-unicode-tags",
        `Rule file contains ${tagMatches.length} Unicode tag character(s) (U+E0000-U+E007F), ` +
          "an ASCII-smuggling channel that hides instructions from human reviewers",
        { evidence: `line ${lineNumber}: ${tagMatches.length} tag character(s)`, line: lineNumber },
        "HIGH",
        {
          observed: [
            "The file embeds Unicode tag characters that render as nothing in editors and diffs.",
            "Tag characters encode invisible ASCII that still reaches models that read the file.",
          ],
          inference:
            "Invisible tag-character content is a known prompt-injection smuggling technique.",
          notVerified: ["CodeGate did not decode or follow any smuggled instruction."],
        },
      ),
    );
  }

  return findings;
}

function encodedPayloadFindings(input: RuleFileInput, lines: string[]): Finding[] {
  return scanEncodedPayloads(input.textContent).map((match: EncodedPayloadMatch) => {
    const severity: Finding["severity"] = match.matchesRemoteShell ? "CRITICAL" : "HIGH";
    const behaviors = [
      match.matchesRemoteShell ? "remote shell execution" : null,
      match.matchesOverridePhrase ? "instruction override" : null,
      match.matchesSensitiveExfil ? "sensitive-data exfiltration" : null,
      match.matchesCommandExecution ? "command execution" : null,
    ].filter((entry): entry is string => entry !== null);

    const sourceLine = lines[match.line - 1] ?? "";
    const evidence: FindingEvidence = {
      evidence:
        `line ${match.line}\n${match.line} | ${sourceLine.slice(0, 200)}\n` +
        `decoded (${match.kind}): ${match.decodedExcerpt}`,
      line: match.line,
      column: 1,
    };

    return makeFinding(
      input.filePath,
      `encoded_payload:${match.line}`,
      "rule-file-encoded-payload",
      `Rule file contains a ${match.kind}-encoded payload that decodes to ${behaviors.join(", ")}`,
      evidence,
      severity,
      {
        observed: [
          `An encoded ${match.kind} blob decodes to readable instructions.`,
          `The decoded content matches: ${behaviors.join(", ")}.`,
        ],
        inference: "Encoding hides the payload from human review while keeping it machine-usable.",
        notVerified: [
          "CodeGate did not execute any decoded instruction.",
          "CodeGate did not fetch any URL referenced by the decoded content.",
        ],
      },
    );
  });
}

export function detectRuleFileIssues(input: RuleFileInput): Finding[] {
  const findings: Finding[] = [];
  const hiddenRemoteShellIncident: FindingNarrative = {
    incidentId: "hidden-remote-shell-payload",
    incidentTitle: "Hidden remote shell payload in skill file",
  };

  findings.push(...hiddenUnicodeFindings(input));

  const originalLines = input.textContent.split(/\r?\n/u);
  const lines: NormalizedLines = {
    original: originalLines,
    normalized: originalLines.map((line) => normalizeForMatching(line)),
  };

  const hiddenCommentPayload = detectHiddenCommentPayload(input, lines.original);
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

  for (let index = 0; index < lines.normalized.length; index += 1) {
    const normalized = lines.normalized[index] ?? "";
    const match = normalized.match(REMOTE_INSTRUCTION_INDIRECTION_PATTERN);
    if (!match || hasNegationBefore(normalized, match.index ?? 0)) {
      continue;
    }
    findings.push(
      makeFinding(
        input.filePath,
        "remote_instruction_indirection",
        "rule-file-remote-instruction-indirection",
        "Rule file directs the agent to fetch and follow instructions from a remote URL",
        buildLineEvidence(lines.original[index] ?? "", index + 1, (match.index ?? 0) + 1),
        "HIGH",
        {
          observed: [
            "The file tells the agent to read or follow instructions hosted at an external URL.",
          ],
          inference:
            "Remote instructions can change at any time after review, so the effective behavior is not what was audited.",
          notVerified: ["CodeGate did not fetch the referenced URL."],
        },
      ),
    );
    break;
  }

  findings.push(...encodedPayloadFindings(input, lines.original));

  const longLineIndex = lines.normalized.findIndex(
    (normalized, index) =>
      (lines.original[index] ?? "").length > 300 &&
      SUSPICIOUS_LONG_LINE_PATTERN.test(normalized) &&
      !NEGATION_PATTERN.test(normalized),
  );
  if (longLineIndex >= 0) {
    const lineNumber = longLineIndex + 1;
    const evidence: FindingEvidence = {
      evidence: `line ${lineNumber}\n${lineNumber} | ${lines.original[longLineIndex]}`,
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
