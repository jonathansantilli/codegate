import { resolve } from "node:path";

export function normalizeSlashes(value: string): string {
  return value.replaceAll("\\", "/");
}

export function resolveForHost(...paths: string[]): string {
  return normalizeSlashes(resolve(...paths));
}

export function normalizeLines(lines: string[]): string[] {
  return lines.map(normalizeSlashes);
}
