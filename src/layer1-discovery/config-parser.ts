import { readFileSync } from "node:fs";
import dotenv from "dotenv";
import yaml from "js-yaml";
import { parse as parseJsonc, printParseErrorCode, type ParseError } from "jsonc-parser";
import { parse as parseToml } from "smol-toml";
import type { DiscoveryFormat } from "../types/discovery.js";

export interface ParseSuccess {
  ok: true;
  data: unknown;
}

export interface ParseFailure {
  ok: false;
  error: string;
}

export type ParseResult = ParseSuccess | ParseFailure;

function fail(error: unknown): ParseFailure {
  const message = error instanceof Error ? error.message : String(error);
  return { ok: false, error: `parse error: ${message}` };
}

export function parseConfigFile(path: string, format: DiscoveryFormat): ParseResult {
  try {
    const content = readFileSync(path, "utf8");
    if (content.includes("\u0000")) {
      return fail(new Error("binary or corrupt file content"));
    }

    if (format === "json") {
      return { ok: true, data: JSON.parse(content) as unknown };
    }

    if (format === "jsonc") {
      const errors: ParseError[] = [];
      const data = parseJsonc(content, errors);
      if (errors.length > 0) {
        const firstError = errors[0];
        return fail(
          new Error(
            `jsonc ${printParseErrorCode(firstError.error)} at offset ${firstError.offset}`,
          ),
        );
      }
      return { ok: true, data: data as unknown };
    }

    if (format === "toml") {
      return { ok: true, data: parseToml(content) as unknown };
    }

    if (format === "yaml") {
      return { ok: true, data: yaml.load(content) as unknown };
    }

    if (format === "dotenv") {
      return { ok: true, data: dotenv.parse(content) as unknown };
    }

    if (format === "text" || format === "markdown") {
      return { ok: true, data: content };
    }

    return fail(new Error(`unsupported format: ${format}`));
  } catch (error) {
    return fail(error);
  }
}
