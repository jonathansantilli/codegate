import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";

export interface CommandExecInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  knownSafeMcpServers: string[];
  knownSafeFormatters: string[];
  knownSafeLspServers: string[];
  blockedCommands: string[];
}

interface CommandEntry {
  path: string;
  contextPath: string;
  command: string[];
  context: Record<string, unknown>;
}

const LAUNCHERS = new Set(["npx", "uvx", "node", "python", "python3", "deno", "bun"]);
const SHELL_META_PATTERN = /[|;&`]|[$][(]/u;
const COMMAND_FIELD_KEYS = new Set([
  "command",
  "cmd",
  "run",
  "runcommand",
  "script",
  "exec",
  "execute",
  "shell",
  "shellcommand",
  "commandline",
]);
const TEMPLATE_COMMAND_KEYS = new Set([
  "command",
  "cmd",
  "run",
  "runcommand",
  "script",
  "exec",
  "execute",
  "shell",
  "shellcommand",
  "commandline",
  "program",
  "binary",
  "executable",
  "file",
  "launcher",
]);
const TEMPLATE_ARGUMENT_KEYS = new Set([
  "args",
  "arguments",
  "commandarguments",
  "argv",
  "params",
  "parameters",
  "commandargs",
]);
const IMPLICIT_COMMAND_CONTEXT_KEYS = new Set([
  "hook",
  "hooks",
  "workflow",
  "workflows",
  "mcp",
  "mcpserver",
  "mcpservers",
  "server",
  "servers",
  "plugin",
  "plugins",
  "extension",
  "extensions",
  "formatter",
  "formatters",
  "lsp",
  "lsps",
  "command",
  "commands",
  "run",
  "exec",
  "execute",
  "script",
]);

function makeFinding(
  filePath: string,
  field: string,
  ruleId: string,
  severity: Finding["severity"],
  description: string,
  evidence?: FindingEvidence | null,
): Finding {
  const location: Finding["location"] = { field };
  if (typeof evidence?.line === "number") {
    location.line = evidence.line;
  }
  if (typeof evidence?.column === "number") {
    location.column = evidence.column;
  }

  return {
    rule_id: ruleId,
    finding_id: `COMMAND_EXEC-${filePath}-${field}`,
    severity,
    category: "COMMAND_EXEC",
    layer: "L2",
    file_path: filePath,
    location,
    description,
    affected_tools: [
      "claude-code",
      "codex-cli",
      "opencode",
      "cursor",
      "windsurf",
      "github-copilot",
    ],
    cve: null,
    owasp: ["ASI02", "ASI05"],
    cwe: "CWE-78",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field", "replace_with_default"],
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeKey(value: string): string {
  return value.replace(/[^a-z0-9]/giu, "").toLowerCase();
}

function extractPackageFromPath(token: string): string | null {
  const normalized = token.replaceAll("\\", "/");
  const scopedMatch = normalized.match(/node_modules\/(@[^/]+\/[^/]+)/u);
  if (scopedMatch?.[1]) {
    return scopedMatch[1];
  }
  const plainMatch = normalized.match(/node_modules\/([^/]+)/u);
  return plainMatch?.[1] ?? null;
}

function extractIdentifier(tokens: string[]): string | null {
  for (const token of tokens) {
    if (token.startsWith("-")) {
      continue;
    }
    if (LAUNCHERS.has(token)) {
      continue;
    }

    const fromPath = extractPackageFromPath(token);
    if (fromPath) {
      return fromPath;
    }

    return token;
  }
  return null;
}

function normalizeIdentifier(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return "";
  }

  const fromPath = extractPackageFromPath(trimmed);
  const candidate = (fromPath ?? trimmed)
    .replaceAll("\\", "/")
    .replace(/[#?].*$/u, "")
    .replace(/\/+$/u, "");

  const looksLikePackageOrTool = /^@?[a-z0-9._-]+(?:\/[a-z0-9._-]+)?$/iu.test(candidate);
  return looksLikePackageOrTool ? candidate.toLowerCase() : candidate;
}

function isAllowlistedIdentifier(identifier: string, allowlist: string[]): boolean {
  const normalizedIdentifier = normalizeIdentifier(identifier);
  if (normalizedIdentifier.length === 0) {
    return false;
  }
  const normalizedAllowlist = new Set(
    allowlist.map((entry) => normalizeIdentifier(entry)).filter((entry) => entry.length > 0),
  );
  return normalizedAllowlist.has(normalizedIdentifier);
}

function commandTokensFromValue(value: unknown): string[] | null {
  if (typeof value === "string") {
    const tokens = value.split(/\s+/u).filter((part) => part.length > 0);
    return tokens.length > 0 ? tokens : null;
  }

  if (Array.isArray(value) && value.every((token) => typeof token === "string")) {
    const tokens = value.map((token) => token.trim()).filter((token) => token.length > 0);
    return tokens.length > 0 ? tokens : null;
  }

  return null;
}

function commandTokensFromTemplateObject(value: Record<string, unknown>): string[] | null {
  let commandTokens: string[] | null = null;
  const argumentTokens: string[] = [];
  const nestedCommandTemplates: Array<Record<string, unknown>> = [];

  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = normalizeKey(key);

    if (TEMPLATE_COMMAND_KEYS.has(normalizedKey)) {
      const direct = commandTokensFromValue(child);
      if (!commandTokens && direct) {
        commandTokens = direct;
        continue;
      }
      if (!commandTokens && isRecord(child)) {
        nestedCommandTemplates.push(child);
      }
      continue;
    }

    if (TEMPLATE_ARGUMENT_KEYS.has(normalizedKey)) {
      const parsedArgs = commandTokensFromValue(child);
      if (parsedArgs) {
        argumentTokens.push(...parsedArgs);
      }
    }
  }

  if (!commandTokens) {
    for (const nested of nestedCommandTemplates) {
      const nestedTokens = commandTokensFromTemplateObject(nested);
      if (!nestedTokens) {
        continue;
      }
      commandTokens = nestedTokens;
      break;
    }
  }

  if (!commandTokens) {
    return null;
  }

  return [...commandTokens, ...argumentTokens];
}

function isLikelyExecutableContext(path: string): boolean {
  const segments = path.split(".").map((segment) => normalizeKey(segment));
  return segments.some((segment) => IMPLICIT_COMMAND_CONTEXT_KEYS.has(segment));
}

function isAllowlisted(identifier: string | null, path: string, input: CommandExecInput): boolean {
  if (!identifier) {
    return false;
  }

  if (path.includes("formatter")) {
    return isAllowlistedIdentifier(identifier, input.knownSafeFormatters);
  }
  if (path.includes("lsp")) {
    return isAllowlistedIdentifier(identifier, input.knownSafeLspServers);
  }
  return isAllowlistedIdentifier(identifier, input.knownSafeMcpServers);
}

function collectCommandEntries(value: unknown, prefix = ""): CommandEntry[] {
  if (!value || typeof value !== "object") {
    return [];
  }

  const record = value as Record<string, unknown>;
  const entries: CommandEntry[] = [];
  const hasExplicitCommandField = Object.keys(record).some((key) =>
    COMMAND_FIELD_KEYS.has(normalizeKey(key)),
  );

  if (!hasExplicitCommandField && prefix.length > 0 && isLikelyExecutableContext(prefix)) {
    const implicitCommandTokens = commandTokensFromTemplateObject(record);
    if (implicitCommandTokens) {
      entries.push({
        path: prefix,
        contextPath: prefix,
        command: implicitCommandTokens,
        context: record,
      });
    }
  }

  for (const [key, child] of Object.entries(record)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (COMMAND_FIELD_KEYS.has(normalizeKey(key))) {
      const directCommandTokens = commandTokensFromValue(child);
      if (directCommandTokens) {
        entries.push({
          path,
          contextPath: prefix,
          command: directCommandTokens,
          context: record,
        });
      } else if (isRecord(child)) {
        const objectCommandTokens = commandTokensFromTemplateObject(child);
        if (objectCommandTokens) {
          entries.push({
            path,
            contextPath: path,
            command: objectCommandTokens,
            context: child,
          });
        }
      }
      continue;
    }
    entries.push(...collectCommandEntries(child, path));
  }

  return entries;
}

function normalizeMarkupCommandText(value: string): string {
  return value
    .replace(/<[^>]+>/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
}

function collectMarkdownExecuteCommandEntries(value: string): CommandEntry[] {
  const entries: CommandEntry[] = [];
  const executeCommandPattern = /<execute_command\b[^>]*>([\s\S]*?)<\/execute_command>/giu;
  const commandPattern = /<command\b[^>]*>([\s\S]*?)<\/command>/giu;
  let commandIndex = 0;

  for (const executeMatch of value.matchAll(executeCommandPattern)) {
    const block = executeMatch[1];
    if (typeof block !== "string" || block.length === 0) {
      continue;
    }

    for (const commandMatch of block.matchAll(commandPattern)) {
      const commandText = commandMatch[1];
      if (typeof commandText !== "string") {
        continue;
      }
      const normalized = normalizeMarkupCommandText(commandText);
      const commandTokens = commandTokensFromValue(normalized);
      if (!commandTokens) {
        continue;
      }

      const path = `markdown.execute_command.${commandIndex}`;
      entries.push({
        path,
        contextPath: path,
        command: commandTokens,
        context: {},
      });
      commandIndex += 1;
    }
  }

  return entries;
}

export function detectCommandExecution(input: CommandExecInput): Finding[] {
  const findings: Finding[] = [];
  const entries = [
    ...collectCommandEntries(input.parsed),
    ...(typeof input.parsed === "string" ? collectMarkdownExecuteCommandEntries(input.parsed) : []),
  ];

  for (const entry of entries) {
    const identifier = extractIdentifier(entry.command);
    if (isAllowlisted(identifier, entry.path, input)) {
      continue;
    }

    const commandLine = entry.command.join(" ");
    const hasBlockedBinary = entry.command.some((token) => input.blockedCommands.includes(token));
    const hasShellMeta = SHELL_META_PATTERN.test(commandLine);
    const hasNetworkUtility = /\b(curl|wget|nc|ncat|socat)\b/u.test(commandLine);

    if (hasBlockedBinary || hasShellMeta || hasNetworkUtility) {
      const evidenceValue = `${entry.path} = ${JSON.stringify(entry.command)}`;
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: [entry.contextPath, entry.path],
        searchTerms: [commandLine, ...entry.command],
        fallbackValue: evidenceValue,
      });
      findings.push(
        makeFinding(
          input.filePath,
          entry.path,
          "command-exec-suspicious",
          "CRITICAL",
          `Suspicious command execution pattern detected: ${commandLine}`,
          evidence,
        ),
      );
    }

    if (
      (entry.context.stdout === "ignore" || entry.context.stderr === "ignore") &&
      (entry.path.includes("formatter") || entry.contextPath.includes("formatter"))
    ) {
      const stdoutField = entry.contextPath.length > 0 ? `${entry.contextPath}.stdout` : "stdout";
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: [stdoutField, entry.contextPath],
        searchTerms: ["stdout", "ignore"],
        fallbackValue: `${stdoutField} = ${JSON.stringify(entry.context.stdout)}`,
      });
      findings.push(
        makeFinding(
          input.filePath,
          stdoutField,
          "formatter-output-suppression",
          "HIGH",
          "Formatter output suppression hides command output",
          evidence,
        ),
      );
    }
  }

  return findings;
}
