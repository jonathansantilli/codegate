import { activeOverridePhrases } from "./override-phrases.js";

/**
 * Shared threat patterns for instruction/rule-file text and MCP tool
 * descriptions. Callers are expected to match against text run through
 * normalizeForMatching() so hidden-character and homoglyph obfuscation
 * cannot dodge these literals.
 */

export const NEGATION_PATTERN = /\b(?:must not|should not|do not|don't|never)\b/iu;

export const SENSITIVE_READ_PATTERN =
  /\b(?:read|cat)\s+(?:~\/\.ssh(?:\/[^\s]+)?|\.env\b|~\/\.[a-z0-9._-]+(?:\/[^\s]+)*)/iu;

export const SENSITIVE_FILE_PATTERN =
  /(~\/\.ssh|~\/\.aws|id_rsa|\.env|credentials|\.git-credentials)/iu;

export const OUTBOUND_TRANSFER_PATTERN =
  /\b(?:upload externally|send to (?:an |a )?(?:external )?(?:webhook|endpoint|server)|curl\b|wget\b|invoke-webrequest\b|post to\b|https?:\/\/|exfiltrat(?:e|ion|ing))\b/iu;

export const EXFIL_PATTERN = /(send .*https?:\/\/|upload|webhook|post to|exfiltrat)/iu;

export const COMMAND_EXECUTION_PATTERN = /(run command|execute shell|bash -c|sh -c|powershell)/iu;

export const REMOTE_SHELL_PATTERN =
  /\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:bash|sh)\b|\b(?:invoke-webrequest|iwr)\b[^\n|]{0,240}\|\s*(?:iex|invoke-expression)\b/iu;

export const SUSPICIOUS_LONG_LINE_PATTERN =
  /\b(?:ignore previous instructions|skip permissions|bypass permissions|upload externally|curl\b|wget\b|https?:\/\/|bash\s+-lc|sh\s+-c|powershell\b|base64\b|~\/\.ssh|\.env\b)\b/iu;

export const HTML_COMMENT_PATTERN = /<!--([\s\S]*?)-->/gu;

export const COMMENT_PAYLOAD_PATTERN =
  /\b(?:secret instructions|ignore previous instructions|curl\b|wget\b|invoke-webrequest\b|bash\b|powershell\b|session share\b|profile sync\b)\b/iu;

export const COOKIE_EXPORT_PATTERN = /\bcookies?\s+(?:export|import|get)\b/iu;
export const SESSION_SHARE_PATTERN = /\bsession\s+share\b|\blive url\b/iu;
export const PROFILE_SYNC_PATTERN =
  /\bprofile\s+sync\b|\breal chrome\b|\blogin sessions\b|\bsession tokens?\b|--profile\b/iu;

export const BOOTSTRAP_INSTALL_PATTERN =
  /\b(?:npm|pnpm|yarn|bun)\s+install\s+-g\b|\bbrew\s+install\b|\bpipx\s+install\b|\bgo\s+install\b|\b(?:npx|pnpx|uvx)\b[^\n`]{0,160}@latest\b/iu;

export const AGENT_CONTROL_POINT_PATTERN =
  /\.claude\/hooks\/|\.claude\/settings\.json|\.claude\/agents\/|\bclaude\.md\b|\bagents\.md\b|\bmcp configuration\b/iu;

export const RESTART_LOAD_PATTERN =
  /\brestart\b.*\b(?:load|take effect|activate|reload|work)\b|\bonly load after restart\b|\bafter restarting\b/iu;

export const REMOTE_INSTRUCTION_INDIRECTION_PATTERN =
  /\b(?:follow|read|fetch|apply|obey|execute)\b[^\n]{0,40}\b(?:instructions|steps|guide|rules|directives)\b[^\n]{0,40}https?:\/\//iu;

export interface OverridePhraseMatch {
  phrase: string;
  index: number;
}

function hasNearbyNegation(normalizedLine: string, matchIndex: number): boolean {
  const prefix = normalizedLine.slice(Math.max(0, matchIndex - 24), matchIndex);
  return NEGATION_PATTERN.test(prefix);
}

/**
 * Find the first instruction-override phrase in a normalized line, skipping
 * matches preceded by nearby negation ("never bypass permissions").
 */
export function findOverridePhrase(normalizedLine: string): OverridePhraseMatch | null {
  for (const { phrase } of activeOverridePhrases()) {
    const matchIndex = normalizedLine.indexOf(phrase);
    if (matchIndex < 0 || hasNearbyNegation(normalizedLine, matchIndex)) {
      continue;
    }
    return { phrase, index: matchIndex };
  }
  return null;
}

export function hasNegationBefore(normalizedLine: string, matchIndex: number): boolean {
  return hasNearbyNegation(normalizedLine, matchIndex);
}
