import { normalizeForMatching } from "./normalize.js";
import {
  COMMAND_EXECUTION_PATTERN,
  EXFIL_PATTERN,
  REMOTE_SHELL_PATTERN,
  SENSITIVE_FILE_PATTERN,
  findOverridePhrase,
} from "./threat-patterns.js";

/**
 * Bounded decode-and-rescan for base64/hex blobs embedded in instruction
 * files and tool descriptions. Hard limits keep this pass cheap and
 * non-explosive: one nesting level, capped blob count and decoded size.
 */

const BASE64_RUN_PATTERN = /[A-Za-z0-9+/_-]{40,}={0,2}/gu;
const HEX_RUN_PATTERN = /(?:[0-9a-fA-F]{2}){30,}/gu;
const MAX_BLOBS_PER_TEXT = 20;
const MAX_DECODED_BYTES = 64 * 1024;
const MIN_PRINTABLE_RATIO = 0.3;
const DECODED_EXCERPT_LENGTH = 160;

export const ENCODED_PAYLOAD_KIND = {
  Base64: "base64",
  Hex: "hex",
} as const;
export type EncodedPayloadKind = (typeof ENCODED_PAYLOAD_KIND)[keyof typeof ENCODED_PAYLOAD_KIND];

export interface EncodedPayloadMatch {
  kind: EncodedPayloadKind;
  line: number;
  decodedExcerpt: string;
  matchesRemoteShell: boolean;
  matchesOverridePhrase: boolean;
  matchesSensitiveExfil: boolean;
  matchesCommandExecution: boolean;
}

function printableRatio(text: string): number {
  if (text.length === 0) {
    return 0;
  }
  let printable = 0;
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    if (code === 0x09 || code === 0x0a || code === 0x0d || (code >= 0x20 && code < 0x7f)) {
      printable += 1;
    }
  }
  return printable / text.length;
}

function decodeBase64(blob: string): string | null {
  // Normalize base64url variants before decoding.
  const normalized = blob.replace(/-/gu, "+").replace(/_/gu, "/");
  try {
    const decoded = Buffer.from(normalized, "base64");
    if (decoded.length === 0 || decoded.length > MAX_DECODED_BYTES) {
      return null;
    }
    return decoded.toString("utf8");
  } catch {
    return null;
  }
}

function decodeHex(blob: string): string | null {
  try {
    const decoded = Buffer.from(blob, "hex");
    if (decoded.length === 0 || decoded.length > MAX_DECODED_BYTES) {
      return null;
    }
    return decoded.toString("utf8");
  } catch {
    return null;
  }
}

function lineNumberAt(text: string, index: number): number {
  return text.slice(0, index).split(/\r?\n/u).length;
}

function isDataImageUri(text: string, blobIndex: number): boolean {
  const prefixStart = Math.max(0, blobIndex - 40);
  return /data:image\/[a-z+.-]+;base64,?$/iu.test(text.slice(prefixStart, blobIndex));
}

function analyzeDecoded(
  kind: EncodedPayloadKind,
  line: number,
  decoded: string,
): EncodedPayloadMatch | null {
  if (printableRatio(decoded) < MIN_PRINTABLE_RATIO) {
    return null;
  }

  const normalized = normalizeForMatching(decoded);
  const matchesRemoteShell = REMOTE_SHELL_PATTERN.test(normalized);
  const matchesOverridePhrase = findOverridePhrase(normalized) !== null;
  const matchesSensitiveExfil =
    SENSITIVE_FILE_PATTERN.test(normalized) && EXFIL_PATTERN.test(normalized);
  const matchesCommandExecution = COMMAND_EXECUTION_PATTERN.test(normalized);

  if (
    !matchesRemoteShell &&
    !matchesOverridePhrase &&
    !matchesSensitiveExfil &&
    !matchesCommandExecution
  ) {
    return null;
  }

  return {
    kind,
    line,
    decodedExcerpt: decoded.slice(0, DECODED_EXCERPT_LENGTH),
    matchesRemoteShell,
    matchesOverridePhrase,
    matchesSensitiveExfil,
    matchesCommandExecution,
  };
}

/** Scan text for encoded blobs whose decoded content matches threat patterns. */
export function scanEncodedPayloads(text: string): EncodedPayloadMatch[] {
  const matches: EncodedPayloadMatch[] = [];
  let blobsSeen = 0;

  const scanRuns = (
    pattern: RegExp,
    kind: EncodedPayloadKind,
    decode: (blob: string) => string | null,
  ): void => {
    pattern.lastIndex = 0;
    let match = pattern.exec(text);
    while (match && blobsSeen < MAX_BLOBS_PER_TEXT) {
      blobsSeen += 1;
      const blob = match[0];
      if (kind === ENCODED_PAYLOAD_KIND.Base64 && isDataImageUri(text, match.index)) {
        match = pattern.exec(text);
        continue;
      }
      const decoded = decode(blob);
      if (decoded) {
        const analyzed = analyzeDecoded(kind, lineNumberAt(text, match.index), decoded);
        if (analyzed) {
          matches.push(analyzed);
        }
      }
      match = pattern.exec(text);
    }
  };

  scanRuns(BASE64_RUN_PATTERN, ENCODED_PAYLOAD_KIND.Base64, decodeBase64);
  scanRuns(HEX_RUN_PATTERN, ENCODED_PAYLOAD_KIND.Hex, decodeHex);

  return matches;
}
