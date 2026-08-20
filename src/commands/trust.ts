import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parse as parseJsonc } from "jsonc-parser";
import { expandHomePath } from "../config/trust.js";

export interface TrustStoreDeps {
  homeDir: () => string;
  pathExists: (path: string) => boolean;
  readFile: (path: string) => string;
  writeFile: (path: string, content: string) => void;
}

const defaultTrustStoreDeps: TrustStoreDeps = {
  homeDir: () => homedir(),
  pathExists: (path) => existsSync(path),
  readFile: (path) => readFileSync(path, "utf8"),
  writeFile: (path, content) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content, "utf8");
  },
};

export interface TrustActionResult {
  configPath: string;
  directory: string;
  changed: boolean;
  trustedDirectories: string[];
}

function resolveConfigPath(configPath: string | undefined, deps: TrustStoreDeps): string {
  return configPath ?? join(deps.homeDir(), ".codegate", "config.json");
}

function readConfigObject(path: string, deps: TrustStoreDeps): Record<string, unknown> {
  if (!deps.pathExists(path)) {
    return {};
  }
  const parsed = parseJsonc(deps.readFile(path)) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Invalid config file: ${path}`);
  }
  return parsed as Record<string, unknown>;
}

function readTrustedList(config: Record<string, unknown>): string[] {
  const raw = config.trusted_directories;
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
}

function writeConfigObject(
  path: string,
  config: Record<string, unknown>,
  deps: TrustStoreDeps,
): void {
  deps.writeFile(path, `${JSON.stringify(config, null, 2)}\n`);
}

function sameDirectory(left: string, right: string): boolean {
  return resolve(expandHomePath(left)) === resolve(expandHomePath(right));
}

export function listTrustedDirectories(
  input: { configPath?: string } = {},
  deps: TrustStoreDeps = defaultTrustStoreDeps,
): { configPath: string; trustedDirectories: string[] } {
  const configPath = resolveConfigPath(input.configPath, deps);
  const config = readConfigObject(configPath, deps);
  return { configPath, trustedDirectories: readTrustedList(config) };
}

export function addTrustedDirectory(
  input: { dir: string; cwd: string; configPath?: string },
  deps: TrustStoreDeps = defaultTrustStoreDeps,
): TrustActionResult {
  const directory = resolve(input.cwd, expandHomePath(input.dir));
  const configPath = resolveConfigPath(input.configPath, deps);
  const config = readConfigObject(configPath, deps);
  const trusted = readTrustedList(config);

  if (trusted.some((entry) => sameDirectory(entry, directory))) {
    return { configPath, directory, changed: false, trustedDirectories: trusted };
  }

  const next = [...trusted, directory];
  writeConfigObject(configPath, { ...config, trusted_directories: next }, deps);
  return { configPath, directory, changed: true, trustedDirectories: next };
}

export function removeTrustedDirectory(
  input: { dir: string; cwd: string; configPath?: string },
  deps: TrustStoreDeps = defaultTrustStoreDeps,
): TrustActionResult {
  const directory = resolve(input.cwd, expandHomePath(input.dir));
  const configPath = resolveConfigPath(input.configPath, deps);
  const config = readConfigObject(configPath, deps);
  const trusted = readTrustedList(config);

  const next = trusted.filter((entry) => !sameDirectory(entry, directory));
  if (next.length === trusted.length) {
    return { configPath, directory, changed: false, trustedDirectories: trusted };
  }

  writeConfigObject(configPath, { ...config, trusted_directories: next }, deps);
  return { configPath, directory, changed: true, trustedDirectories: next };
}
