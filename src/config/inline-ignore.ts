import type { Finding } from "../types/finding.js";

export interface InlineIgnoreDirectiveSet {
  rules: Set<string>;
  ruleLines: Map<string, Set<number>>;
}

export type InlineIgnoreMap = Map<string, InlineIgnoreDirectiveSet>;

function normalizeRuleId(value: string): string | null {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function addDirective(target: InlineIgnoreDirectiveSet, ruleId: string, line: number): void {
  target.rules.add(ruleId);

  const lines = target.ruleLines.get(ruleId) ?? new Set<number>();
  lines.add(line);
  target.ruleLines.set(ruleId, lines);
}

function parseDirectiveRules(raw: string): string[] {
  return raw
    .split(",")
    .map((entry) => normalizeRuleId(entry))
    .filter((entry): entry is string => entry !== null);
}

export function collectInlineIgnoreDirectives(
  files: Array<{ filePath: string; textContent: string }>,
): InlineIgnoreMap {
  const directives: InlineIgnoreMap = new Map();
  const pattern = /codegate:\s*ignore\[([^\]]+)\]/giu;

  for (const file of files) {
    const lines = file.textContent.split(/\r?\n/u);
    let directiveSet = directives.get(file.filePath);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      pattern.lastIndex = 0;

      for (const match of line.matchAll(pattern)) {
        const ruleIds = parseDirectiveRules(match[1] ?? "");
        if (ruleIds.length === 0) {
          continue;
        }

        if (!directiveSet) {
          directiveSet = {
            rules: new Set<string>(),
            ruleLines: new Map<string, Set<number>>(),
          };
          directives.set(file.filePath, directiveSet);
        }

        for (const ruleId of ruleIds) {
          addDirective(directiveSet, ruleId, index + 1);
        }
      }
    }
  }

  return directives;
}

export function applyInlineIgnoreDirectives<T extends Finding>(
  findings: T[],
  directives: InlineIgnoreMap,
): T[] {
  return findings.map((finding) => {
    const set = directives.get(finding.file_path);
    if (!set || !set.rules.has(finding.rule_id)) {
      return finding;
    }

    return {
      ...finding,
      suppressed: true,
    };
  });
}
