import { CONFUSABLE_TO_LATIN } from "./confusables.js";
import { stripHiddenCharacters } from "./unicode.js";

const confusablePattern = new RegExp(`[${Object.keys(CONFUSABLE_TO_LATIN).join("")}]`, "gu");

function foldConfusables(text: string): string {
  return text.replace(confusablePattern, (char) => CONFUSABLE_TO_LATIN[char] ?? char);
}

/**
 * Normalize text before threat-pattern matching so trivial obfuscation
 * (zero-width splits, tag characters, homoglyphs, compatibility forms)
 * cannot dodge literal patterns:
 *
 *   NFKC -> strip hidden characters -> fold confusables -> lowercase
 *
 * Normalize per line when line numbers matter: evidence must quote the
 * original line while matching runs against the normalized one.
 */
export function normalizeForMatching(text: string): string {
  return foldConfusables(stripHiddenCharacters(text.normalize("NFKC"))).toLowerCase();
}
