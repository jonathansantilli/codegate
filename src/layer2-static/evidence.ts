import { findNodeAtLocation, parseTree, type Node as JsonNode } from "jsonc-parser";

export interface FindingEvidence {
  evidence: string;
  line?: number;
  column?: number;
}

export interface BuildFindingEvidenceInput {
  textContent: string;
  jsonPaths?: string[];
  searchTerms?: string[];
  fallbackValue?: string;
}

function toLineStarts(textContent: string): number[] {
  const starts = [0];
  for (let index = 0; index < textContent.length; index += 1) {
    if (textContent.charCodeAt(index) === 10) {
      starts.push(index + 1);
    }
  }
  return starts;
}

function offsetToLineAndColumn(
  lineStarts: number[],
  offset: number,
): { line: number; column: number } {
  if (lineStarts.length === 0) {
    return { line: 1, column: 1 };
  }

  let low = 0;
  let high = lineStarts.length - 1;
  let lineIndex = 0;

  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    if (lineStarts[mid] <= offset) {
      lineIndex = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  return {
    line: lineIndex + 1,
    column: offset - lineStarts[lineIndex] + 1,
  };
}

function formatLineBlock(
  textContent: string,
  startLine: number,
  endLine: number,
  startColumn?: number,
): FindingEvidence {
  const lines = textContent.split(/\r?\n/u);
  const snippetLines = lines.slice(startLine - 1, endLine);
  const numberedLines = snippetLines.map((line, index) => `${startLine + index} | ${line}`);
  const header = startLine === endLine ? `line ${startLine}` : `lines ${startLine}-${endLine}`;
  return {
    evidence: [header, ...numberedLines].join("\n"),
    line: startLine,
    column: startColumn,
  };
}

function splitJsonPath(path: string): Array<string | number> {
  return path
    .split(".")
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0)
    .map((segment) => {
      if (/^[0-9]+$/u.test(segment)) {
        return Number(segment);
      }
      return segment;
    });
}

function normalizeSnippetNode(node: JsonNode): JsonNode {
  if (node.parent?.type === "property") {
    return node.parent;
  }
  return node;
}

function extractEvidenceFromJsonPath(textContent: string, path: string): FindingEvidence | null {
  if (path.length === 0) {
    return null;
  }

  const root = parseTree(textContent);
  if (!root) {
    return null;
  }

  const node = findNodeAtLocation(root, splitJsonPath(path));
  if (!node) {
    return null;
  }

  const snippetNode = normalizeSnippetNode(node);
  const startOffset = snippetNode.offset;
  const endOffset = snippetNode.offset + snippetNode.length;
  const lineStarts = toLineStarts(textContent);
  const start = offsetToLineAndColumn(lineStarts, startOffset);
  const end = offsetToLineAndColumn(lineStarts, Math.max(startOffset, endOffset - 1));
  return formatLineBlock(textContent, start.line, end.line, start.column);
}

function extractEvidenceFromSearchTerm(textContent: string, term: string): FindingEvidence | null {
  if (term.length === 0) {
    return null;
  }

  const offset = textContent.indexOf(term);
  if (offset < 0) {
    return null;
  }

  const lineStarts = toLineStarts(textContent);
  const position = offsetToLineAndColumn(lineStarts, offset);
  return formatLineBlock(textContent, position.line, position.line, position.column);
}

function uniqueValues(values: string[]): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];

  for (const value of values) {
    const normalized = value.trim();
    if (normalized.length === 0 || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    unique.push(normalized);
  }

  return unique;
}

export function buildFindingEvidence(input: BuildFindingEvidenceInput): FindingEvidence | null {
  if (input.textContent.length > 0) {
    const jsonPaths = uniqueValues(input.jsonPaths ?? []);
    for (const path of jsonPaths) {
      const extracted = extractEvidenceFromJsonPath(input.textContent, path);
      if (extracted) {
        return extracted;
      }
    }

    const searchTerms = uniqueValues(input.searchTerms ?? []);
    for (const term of searchTerms) {
      const extracted = extractEvidenceFromSearchTerm(input.textContent, term);
      if (extracted) {
        return extracted;
      }
    }
  }

  if (input.fallbackValue && input.fallbackValue.length > 0) {
    return { evidence: input.fallbackValue };
  }

  return null;
}
