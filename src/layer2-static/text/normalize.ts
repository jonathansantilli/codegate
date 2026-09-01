import { CONFUSABLE_TO_LATIN } from "./confusables.js";
import { stripHiddenCharacters } from "./unicode.js";

const confusablePattern = new RegExp(`[${Object.keys(CONFUSABLE_TO_LATIN).join("")}]`, "gu");

function foldConfusables(text: string): string {
  return text.replace(confusablePattern, (char) => CONFUSABLE_TO_LATIN[char] ?? char);
}

/**
 * Normalize text before threat-pattern matching so trivial obfuscation
 * (zero-width splits, tag characters, homoglyphs, compatibility forms,
 * whitespace) cannot dodge literal patterns:
 *
 *   NFKC -> strip hidden characters -> fold confusables -> lowercase
 *        -> collapse whitespace runs to a single space
 *
 * The whitespace step is the difference between catching a phrase and not.
 * Everything before it defeats homoglyphs and zero-width characters, which is
 * the sophisticated attack — and then "ignore previous  instructions" with two
 * spaces, or a tab, or a line break where the text happened to wrap, walked
 * straight past a literal written with single spaces. Prose wraps at 80
 * columns by default in most editors, so this was not only reachable by an
 * adversary; ordinary formatting did it by accident.
 *
 * Runs collapse rather than disappear: removing whitespace entirely would join
 * words that were never one word and invent matches that are not there.
 *
 * Normalize per line when line numbers matter: evidence must quote the
 * original line while matching runs against the normalized one. Collapsing
 * shifts columns within a line, so the column an evidence pointer reports is
 * approximate where a line held runs of whitespace; the line itself is exact.
 */
export function normalizeForMatching(text: string): string {
  return foldConfusables(stripHiddenCharacters(text.normalize("NFKC")))
    .toLowerCase()
    .replace(/\s+/gu, " ");
}
