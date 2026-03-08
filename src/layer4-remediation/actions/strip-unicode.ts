export interface StripUnicodeResult {
  content: string;
  changed: boolean;
}

const INVISIBLE_UNICODE = /[\u200B-\u200D\u2060\uFEFF]/gu;

export function stripInvisibleUnicode(content: string): StripUnicodeResult {
  const cleaned = content.replace(INVISIBLE_UNICODE, "");
  return {
    content: cleaned,
    changed: cleaned !== content,
  };
}
