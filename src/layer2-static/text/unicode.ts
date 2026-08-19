/**
 * Single source of truth for hidden/invisible Unicode classes used across
 * detectors. Tag characters (U+E0000-U+E007F) are the primary real-world
 * "ASCII smuggling" vector: they encode invisible ASCII that survives
 * copy/paste and reaches models while remaining unseen by human reviewers.
 *
 * All patterns use escape sequences on purpose: this file must never
 * contain literal hidden characters.
 */

export const HIDDEN_UNICODE_CLASS = {
  ZeroWidth: "zero-width",
  Bidi: "bidi",
  Tags: "tags",
  VariationSelector: "variation-selector",
} as const;
export type HiddenUnicodeClass = (typeof HIDDEN_UNICODE_CLASS)[keyof typeof HIDDEN_UNICODE_CLASS];

export const ZERO_WIDTH_PATTERN = /[\u200B-\u200D\u2060\uFEFF]/u;
export const BIDI_CONTROL_PATTERN = /[\u202A-\u202E\u2066-\u2069]/u;
export const TAG_CHARACTER_PATTERN = /[\u{E0000}-\u{E007F}]/u;
export const VARIATION_SELECTOR_PATTERN = /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/u;

// Variation selectors are only suspicious in clusters: payload encodings use
// runs of them, while a single selector legitimately follows an emoji.
const CLUSTERED_VARIATION_SELECTOR_PATTERN = /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]{2,}/u;

// eslint-disable-next-line no-misleading-character-class -- matching the combining/invisible characters themselves is the point
const STRIP_FOR_MATCHING_PATTERN =
  /[\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069\uFE00-\uFE0F\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

export interface HiddenUnicodeMatch {
  index: number;
  codePoint: number;
  class: HiddenUnicodeClass;
}

function classifyCodePoint(codePoint: number): HiddenUnicodeClass | null {
  if (
    (codePoint >= 0x200b && codePoint <= 0x200d) ||
    codePoint === 0x2060 ||
    codePoint === 0xfeff
  ) {
    return HIDDEN_UNICODE_CLASS.ZeroWidth;
  }
  if (
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069)
  ) {
    return HIDDEN_UNICODE_CLASS.Bidi;
  }
  if (codePoint >= 0xe0000 && codePoint <= 0xe007f) {
    return HIDDEN_UNICODE_CLASS.Tags;
  }
  if (
    (codePoint >= 0xfe00 && codePoint <= 0xfe0f) ||
    (codePoint >= 0xe0100 && codePoint <= 0xe01ef)
  ) {
    return HIDDEN_UNICODE_CLASS.VariationSelector;
  }
  return null;
}

/**
 * Find hidden Unicode characters worth flagging. Variation selectors are
 * reported only when clustered (two or more in a row).
 */
export function findHiddenUnicode(text: string): HiddenUnicodeMatch[] {
  const matches: HiddenUnicodeMatch[] = [];
  const clusteredVariationRanges: Array<{ start: number; end: number }> = [];

  const clusterRegex = new RegExp(CLUSTERED_VARIATION_SELECTOR_PATTERN, "gu");
  let clusterMatch = clusterRegex.exec(text);
  while (clusterMatch) {
    clusteredVariationRanges.push({
      start: clusterMatch.index,
      end: clusterMatch.index + clusterMatch[0].length,
    });
    clusterMatch = clusterRegex.exec(text);
  }

  let index = 0;
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    const classified = classifyCodePoint(codePoint);
    if (classified === HIDDEN_UNICODE_CLASS.VariationSelector) {
      const clustered = clusteredVariationRanges.some(
        (range) => index >= range.start && index < range.end,
      );
      if (clustered) {
        matches.push({ index, codePoint, class: classified });
      }
    } else if (classified) {
      matches.push({ index, codePoint, class: classified });
    }
    index += char.length;
  }

  return matches;
}

/** Remove every hidden character class so pattern matching sees the visible text. */
export function stripHiddenCharacters(text: string): string {
  return text.replace(STRIP_FOR_MATCHING_PATTERN, "");
}

export function hasHiddenUnicodeClass(text: string, cls: HiddenUnicodeClass): boolean {
  return findHiddenUnicode(text).some((match) => match.class === cls);
}
