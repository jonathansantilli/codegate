import type { Finding } from "../../types/finding.js";
import { activePopularMcpPackages } from "../data/popular-mcp-packages.js";
import { damerauLevenshtein } from "../text/edit-distance.js";

export interface McpPackageHygieneInput {
  filePath: string;
  parsed: unknown;
  knownSafeMcpServers: string[];
}

const MCP_SERVER_CONTAINER_KEYS = ["mcpServers", "mcp_servers", "context_servers"] as const;

export const PACKAGE_REGISTRY = {
  Npm: "npm",
  Pypi: "pypi",
} as const;
export type PackageRegistry = (typeof PACKAGE_REGISTRY)[keyof typeof PACKAGE_REGISTRY];

const NPM_LAUNCHERS = new Set(["npx", "pnpx", "bunx"]);
const PYPI_LAUNCHERS = new Set(["uvx", "pipx"]);

// Exact versions pin the executed code; tags and ranges resolve at launch time.
const EXACT_NPM_VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[\w.]+)?$/u;
const EXACT_PYPI_VERSION_PATTERN = /^==\s*\d+(?:\.\d+)*(?:[a-z0-9.]*)$/iu;

const MIN_TYPOSQUAT_NAME_LENGTH = 4;

interface PackageLaunch {
  registry: PackageRegistry;
  locator: string;
  serverPath: string;
  autoConfirm: boolean;
}

interface ParsedLocator {
  name: string;
  version: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseNpmLocator(locator: string): ParsedLocator {
  const versionIndex = locator.lastIndexOf("@");
  if (versionIndex > 0) {
    return { name: locator.slice(0, versionIndex), version: locator.slice(versionIndex + 1) };
  }
  return { name: locator, version: null };
}

function parsePypiLocator(locator: string): ParsedLocator {
  const specIndex = locator.search(/[=<>!~]/u);
  if (specIndex > 0) {
    return { name: locator.slice(0, specIndex), version: locator.slice(specIndex) };
  }
  return { name: locator, version: null };
}

export function parsePackageLocator(registry: PackageRegistry, locator: string): ParsedLocator {
  return registry === PACKAGE_REGISTRY.Npm ? parseNpmLocator(locator) : parsePypiLocator(locator);
}

export function isPinnedLocator(registry: PackageRegistry, locator: string): boolean {
  const { version } = parsePackageLocator(registry, locator);
  if (version === null) {
    return false;
  }
  return registry === PACKAGE_REGISTRY.Npm
    ? EXACT_NPM_VERSION_PATTERN.test(version)
    : EXACT_PYPI_VERSION_PATTERN.test(version);
}

function typosquatThreshold(name: string): number {
  return name.length >= 10 ? 2 : 1;
}

export function findLikelyTyposquatTarget(registry: PackageRegistry, name: string): string | null {
  const popular = activePopularMcpPackages()[registry];
  const normalized = name.toLowerCase();
  if (normalized.length < MIN_TYPOSQUAT_NAME_LENGTH || popular.includes(normalized)) {
    return null;
  }

  let best: { target: string; distance: number } | null = null;
  for (const candidate of popular) {
    const distance = damerauLevenshtein(normalized, candidate);
    if (distance > 0 && distance <= typosquatThreshold(normalized)) {
      if (!best || distance < best.distance) {
        best = { target: candidate, distance };
      }
    }
  }
  return best?.target ?? null;
}

function commandTokens(config: Record<string, unknown>): string[] {
  if (Array.isArray(config.command) && config.command.every((entry) => typeof entry === "string")) {
    return config.command as string[];
  }
  if (typeof config.command === "string") {
    const args = Array.isArray(config.args)
      ? (config.args as unknown[]).filter((entry): entry is string => typeof entry === "string")
      : [];
    return [config.command, ...args];
  }
  return [];
}

function firstNonFlag(tokens: string[], startIndex: number): string | null {
  for (let index = startIndex; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (typeof token !== "string" || token.length === 0 || token.startsWith("-")) {
      continue;
    }
    return token;
  }
  return null;
}

function hasAutoConfirmFlag(tokens: string[]): boolean {
  return tokens.some((token) => token === "-y" || token === "--yes");
}

function collectPackageLaunches(value: unknown, path: string, launches: PackageLaunch[]): void {
  if (!isRecord(value)) {
    return;
  }

  for (const containerKey of MCP_SERVER_CONTAINER_KEYS) {
    const container = value[containerKey];
    if (!isRecord(container)) {
      continue;
    }
    for (const [serverName, serverConfig] of Object.entries(container)) {
      if (!isRecord(serverConfig)) {
        continue;
      }
      const tokens = commandTokens(serverConfig);
      if (tokens.length === 0) {
        continue;
      }
      const launcher = (tokens[0] ?? "").toLowerCase();
      const registry = NPM_LAUNCHERS.has(launcher)
        ? PACKAGE_REGISTRY.Npm
        : PYPI_LAUNCHERS.has(launcher)
          ? PACKAGE_REGISTRY.Pypi
          : null;
      if (!registry) {
        continue;
      }
      const locator = firstNonFlag(tokens, 1);
      if (!locator) {
        continue;
      }
      launches.push({
        registry,
        locator,
        serverPath: `${path}${containerKey}.${serverName}`,
        autoConfirm: hasAutoConfirmFlag(tokens),
      });
    }
  }

  for (const [key, nested] of Object.entries(value)) {
    if ((MCP_SERVER_CONTAINER_KEYS as readonly string[]).includes(key)) {
      continue;
    }
    collectPackageLaunches(nested, `${path}${key}.`, launches);
  }
}

function makeFinding(
  input: McpPackageHygieneInput,
  launch: PackageLaunch,
  ruleId: string,
  severity: Finding["severity"],
  description: string,
): Finding {
  return {
    rule_id: ruleId,
    finding_id: `${ruleId.toUpperCase().replaceAll("-", "_")}-${input.filePath}-${launch.serverPath}`,
    severity,
    category: "COMMAND_EXEC",
    layer: "L2",
    file_path: input.filePath,
    location: { field: launch.serverPath },
    description,
    affected_tools: ["claude-code", "codex-cli", "opencode", "cursor", "windsurf"],
    cve: null,
    owasp: ["ASI05"],
    cwe: "CWE-829",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field", "replace_with_default"],
    metadata: {
      sources: [input.filePath, launch.serverPath],
      risk_tags: ["mcp", "supply-chain"],
      origin: "mcp-package-hygiene",
    },
    evidence: `${launch.serverPath}: ${launch.locator}`,
    suppressed: false,
  };
}

export function detectMcpPackageHygiene(input: McpPackageHygieneInput): Finding[] {
  const launches: PackageLaunch[] = [];
  collectPackageLaunches(input.parsed, "", launches);
  if (launches.length === 0) {
    return [];
  }

  const knownSafe = new Set(input.knownSafeMcpServers.map((entry) => entry.toLowerCase()));
  const findings: Finding[] = [];

  for (const launch of launches) {
    const { name } = parsePackageLocator(launch.registry, launch.locator);
    if (knownSafe.has(name.toLowerCase())) {
      continue;
    }

    if (!isPinnedLocator(launch.registry, launch.locator)) {
      const autoConfirmNote = launch.autoConfirm
        ? " The launcher auto-confirms installation (-y), so new versions run without any prompt."
        : "";
      findings.push(
        makeFinding(
          input,
          launch,
          "mcp-unpinned-package",
          "MEDIUM",
          `MCP server runs ${launch.registry} package "${launch.locator}" without an exact version pin, ` +
            `so it executes whatever the registry serves at launch time.${autoConfirmNote}`,
        ),
      );
    }

    const typosquatTarget = findLikelyTyposquatTarget(launch.registry, name);
    if (typosquatTarget) {
      findings.push(
        makeFinding(
          input,
          launch,
          "mcp-possible-typosquat",
          "HIGH",
          `MCP server package "${name}" is one edit away from the well-known package ` +
            `"${typosquatTarget}". Verify this is the intended package and not a typosquat.`,
        ),
      );
    }
  }

  return findings;
}
