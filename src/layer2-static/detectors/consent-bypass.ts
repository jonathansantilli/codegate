import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";

export interface ConsentBypassInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  trustedApiDomains?: string[];
}

const AUTO_APPROVAL_KEYS = new Set(["alwaysallow", "always_allow", "autoapprove", "auto_approve"]);
const REMOTE_MCP_ARRAY_KEYS = ["remoteMCPServers", "remote_mcp_servers"] as const;
const SENSITIVE_REMOTE_MCP_HEADER_KEYS = new Set([
  "authorization",
  "proxyauthorization",
  "cookie",
  "xapikey",
  "apikey",
  "xauthtoken",
  "xaccesstoken",
]);
const ROUTING_REMOTE_MCP_HEADER_KEYS = new Set([
  "host",
  "origin",
  "referer",
  "forwarded",
  "xforwardedhost",
  "xforwardedfor",
  "xrealip",
]);

function normalizeToken(value: string): string {
  return value.replace(/[^a-z0-9]/giu, "").toLowerCase();
}

function hasMeaningfulHeaderValue(value: unknown): boolean {
  if (typeof value === "string") {
    return value.trim().length > 0;
  }
  if (typeof value === "number") {
    return Number.isFinite(value);
  }
  return value === true;
}

function normalizeTrustedDomain(value: string): string | null {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.length === 0) {
    return null;
  }

  try {
    return new URL(trimmed).hostname.toLowerCase();
  } catch {
    const withoutScheme = trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//u, "");
    const domainOnly = withoutScheme.split(/[/?#]/u)[0]?.toLowerCase() ?? "";
    return domainOnly.length > 0 ? domainOnly : null;
  }
}

function isTrustedDomain(hostname: string, trustedDomains: string[]): boolean {
  const lowerHost = hostname.toLowerCase();
  for (const domain of trustedDomains) {
    const normalized = normalizeTrustedDomain(domain);
    if (!normalized) {
      continue;
    }
    if (normalized.startsWith("*.")) {
      const suffix = normalized.slice(1);
      if (lowerHost.endsWith(suffix)) {
        return true;
      }
      continue;
    }
    if (lowerHost === normalized || lowerHost.endsWith(`.${normalized}`)) {
      return true;
    }
  }
  return false;
}

function extractHostFromHeaderValue(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }

  try {
    return new URL(trimmed).hostname.toLowerCase();
  } catch {
    // Continue with host-like parsing.
  }

  const hostLike = trimmed.split(/[/?#]/u)[0] ?? "";
  const normalizedHost = hostLike.replace(/:\d+$/u, "").toLowerCase();
  if (/^[a-z0-9.-]+$/u.test(normalizedHost) && normalizedHost.includes(".")) {
    return normalizedHost;
  }
  return null;
}

function makeFinding(
  filePath: string,
  field: string,
  ruleId: string,
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
    finding_id: `CONSENT_BYPASS-${filePath}-${field}`,
    severity: "CRITICAL",
    category: "CONSENT_BYPASS",
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
    owasp: ["ASI05", "ASI09"],
    cwe: "CWE-78",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field", "replace_with_default"],
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

export function detectConsentBypass(input: ConsentBypassInput): Finding[] {
  const findings: Finding[] = [];
  const trustedApiDomains = input.trustedApiDomains ?? [];
  const parsed = (
    input.parsed && typeof input.parsed === "object"
      ? (input.parsed as Record<string, unknown>)
      : {}
  ) as Record<string, unknown>;

  const stack: Array<{ value: unknown; path: string }> = [{ value: parsed, path: "" }];
  for (const { value, path } of stack) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      continue;
    }
    const record = value as Record<string, unknown>;
    for (const [key, child] of Object.entries(record)) {
      const fieldPath = path.length > 0 ? `${path}.${key}` : key;
      const normalized = key.toLowerCase();
      if (AUTO_APPROVAL_KEYS.has(normalized) && child === true) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [fieldPath],
          searchTerms: [key, normalized],
          fallbackValue: `${fieldPath} = true`,
        });
        findings.push(
          makeFinding(
            input.filePath,
            fieldPath,
            "cross-tool-auto-approval",
            `Cross-tool auto-approval flag is enabled: ${fieldPath}`,
            evidence,
          ),
        );
      }
      stack.push({ value: child, path: fieldPath });
    }
  }

  if (parsed.enableAllProjectMcpServers === true) {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      jsonPaths: ["enableAllProjectMcpServers"],
      searchTerms: ['"enableAllProjectMcpServers"', "enableAllProjectMcpServers"],
      fallbackValue: "enableAllProjectMcpServers = true",
    });
    findings.push(
      makeFinding(
        input.filePath,
        "enableAllProjectMcpServers",
        "claude-mcp-consent-bypass",
        "Project-level MCP auto-approval bypass is enabled",
        evidence,
      ),
    );
  }

  if (Array.isArray(parsed.enabledMcpjsonServers) && parsed.enabledMcpjsonServers.length > 0) {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      jsonPaths: ["enabledMcpjsonServers"],
      searchTerms: ['"enabledMcpjsonServers"', "enabledMcpjsonServers"],
      fallbackValue: `enabledMcpjsonServers = ${JSON.stringify(parsed.enabledMcpjsonServers)}`,
    });
    findings.push(
      makeFinding(
        input.filePath,
        "enabledMcpjsonServers",
        "claude-mcp-server-auto-approval",
        "Specific MCP servers are auto-approved in project config",
        evidence,
      ),
    );
  }

  if (
    Array.isArray(parsed.trustedCommands)
      ? parsed.trustedCommands.length > 0
      : typeof parsed.trustedCommands === "object" && parsed.trustedCommands !== null
  ) {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      jsonPaths: ["trustedCommands"],
      searchTerms: ['"trustedCommands"', "trustedCommands"],
      fallbackValue: `trustedCommands = ${JSON.stringify(parsed.trustedCommands)}`,
    });
    findings.push(
      makeFinding(
        input.filePath,
        "trustedCommands",
        "trusted-commands-consent-bypass",
        "Trusted command allowlist may bypass consent prompts",
        evidence,
      ),
    );
  }

  if (parsed.mcpMarketplaceEnabled === false) {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      jsonPaths: ["mcpMarketplaceEnabled"],
      searchTerms: ['"mcpMarketplaceEnabled"', "mcpMarketplaceEnabled"],
      fallbackValue: "mcpMarketplaceEnabled = false",
    });
    findings.push(
      makeFinding(
        input.filePath,
        "mcpMarketplaceEnabled",
        "cline-mcp-marketplace-disabled",
        "Cline remote policy disables MCP marketplace and local MCP server usage",
        evidence,
      ),
    );
  }

  if (parsed.blockPersonalRemoteMCPServers === true) {
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      jsonPaths: ["blockPersonalRemoteMCPServers"],
      searchTerms: ['"blockPersonalRemoteMCPServers"', "blockPersonalRemoteMCPServers"],
      fallbackValue: "blockPersonalRemoteMCPServers = true",
    });
    findings.push(
      makeFinding(
        input.filePath,
        "blockPersonalRemoteMCPServers",
        "cline-block-personal-remote-mcp",
        "Cline remote policy blocks personal remote MCP servers and enforces organization endpoints",
        evidence,
      ),
    );
  }

  for (const arrayKey of REMOTE_MCP_ARRAY_KEYS) {
    const remoteServers = parsed[arrayKey];
    if (!Array.isArray(remoteServers)) {
      continue;
    }

    remoteServers.forEach((entry, index) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        return;
      }
      const server = entry as Record<string, unknown>;
      const alwaysEnabledField = `${arrayKey}.${index}.alwaysEnabled`;
      if (server.alwaysEnabled === true) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [alwaysEnabledField],
          searchTerms: ['"alwaysEnabled"', "alwaysEnabled", arrayKey],
          fallbackValue: `${alwaysEnabledField} = true`,
        });
        findings.push(
          makeFinding(
            input.filePath,
            alwaysEnabledField,
            "cline-remote-mcp-always-enabled",
            "Cline remote MCP server is configured as always-enabled and cannot be disabled by users",
            evidence,
          ),
        );
      }

      const urlField = `${arrayKey}.${index}.url`;
      let remoteUrlHost: string | null = null;
      if (typeof server.url === "string") {
        let protocol: string;
        try {
          const parsedUrl = new URL(server.url);
          protocol = parsedUrl.protocol;
          remoteUrlHost = parsedUrl.hostname.toLowerCase();
        } catch {
          protocol = "";
        }
        if (protocol === "http:") {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [urlField],
            searchTerms: [server.url],
            fallbackValue: `${urlField} = ${JSON.stringify(server.url)}`,
          });
          findings.push(
            makeFinding(
              input.filePath,
              urlField,
              "cline-remote-mcp-insecure-url",
              `Cline remote MCP server uses insecure HTTP endpoint: ${server.url}`,
              evidence,
            ),
          );
        }

        if (
          protocol === "https:" &&
          remoteUrlHost &&
          trustedApiDomains.length > 0 &&
          !isTrustedDomain(remoteUrlHost, trustedApiDomains)
        ) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [urlField],
            searchTerms: [server.url, remoteUrlHost],
            fallbackValue: `${urlField} = ${JSON.stringify(server.url)}`,
          });
          findings.push(
            makeFinding(
              input.filePath,
              urlField,
              "cline-remote-mcp-unallowlisted-url-domain",
              `Cline remote MCP server URL domain is not allowlisted: ${remoteUrlHost}`,
              evidence,
            ),
          );
        }
      }

      if (!server.headers || typeof server.headers !== "object" || Array.isArray(server.headers)) {
        return;
      }
      for (const [headerName, headerValue] of Object.entries(server.headers)) {
        if (!hasMeaningfulHeaderValue(headerValue)) {
          continue;
        }
        const normalizedHeader = normalizeToken(headerName);
        const headerField = `${arrayKey}.${index}.headers.${headerName}`;

        if (SENSITIVE_REMOTE_MCP_HEADER_KEYS.has(normalizedHeader)) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [headerField, `${arrayKey}.${index}.headers`],
            searchTerms: [headerName],
            fallbackValue: `${headerField} = ${JSON.stringify(headerValue)}`,
          });
          findings.push(
            makeFinding(
              input.filePath,
              headerField,
              "cline-remote-mcp-sensitive-header",
              `Cline remote MCP server config injects sensitive credential-bearing header: ${headerName}`,
              evidence,
            ),
          );
          continue;
        }

        if (ROUTING_REMOTE_MCP_HEADER_KEYS.has(normalizedHeader)) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [headerField, `${arrayKey}.${index}.headers`],
            searchTerms: [headerName],
            fallbackValue: `${headerField} = ${JSON.stringify(headerValue)}`,
          });
          findings.push(
            makeFinding(
              input.filePath,
              headerField,
              "cline-remote-mcp-routing-header",
              `Cline remote MCP server config injects routing/identity override header: ${headerName}`,
              evidence,
            ),
          );

          const headerHost = extractHostFromHeaderValue(headerValue);
          if (
            headerHost &&
            trustedApiDomains.length > 0 &&
            !isTrustedDomain(headerHost, trustedApiDomains)
          ) {
            const domainEvidence = buildFindingEvidence({
              textContent: input.textContent,
              jsonPaths: [headerField, `${arrayKey}.${index}.headers`],
              searchTerms: [headerName, headerHost],
              fallbackValue: `${headerField} = ${JSON.stringify(headerValue)}`,
            });
            findings.push(
              makeFinding(
                input.filePath,
                headerField,
                "cline-remote-mcp-unallowlisted-header-domain",
                `Cline remote MCP routing header references non-allowlisted domain: ${headerHost}`,
                domainEvidence,
              ),
            );
          } else if (
            headerHost &&
            remoteUrlHost &&
            headerHost !== remoteUrlHost &&
            trustedApiDomains.length === 0
          ) {
            const mismatchEvidence = buildFindingEvidence({
              textContent: input.textContent,
              jsonPaths: [headerField, urlField],
              searchTerms: [headerName, headerHost, remoteUrlHost],
              fallbackValue: `${headerField} overrides ${remoteUrlHost} -> ${headerHost}`,
            });
            findings.push(
              makeFinding(
                input.filePath,
                headerField,
                "cline-remote-mcp-header-host-mismatch",
                `Cline remote MCP routing header host differs from server URL host (${remoteUrlHost} -> ${headerHost})`,
                mismatchEvidence,
              ),
            );
          }
        }
      }
    });
  }

  const patterns = [
    { match: "--dangerously-skip-permissions", evidenceTerms: ["--dangerously-skip-permissions"] },
    { match: "--trust-all-tools", evidenceTerms: ["--trust-all-tools"] },
    { match: "--no-interactive", evidenceTerms: ["--no-interactive"] },
    { match: "alwaysallow", evidenceTerms: ["alwaysAllow", "alwaysallow"] },
    { match: "always_allow", evidenceTerms: ["always_allow"] },
    { match: "autoapprove", evidenceTerms: ["autoApprove", "autoapprove"] },
    { match: "auto_approve", evidenceTerms: ["auto_approve"] },
    { match: "yolo", evidenceTerms: ["YOLO", "yolo"] },
  ] as const;

  const lower = input.textContent.toLowerCase();
  for (const pattern of patterns) {
    if (lower.includes(pattern.match)) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        searchTerms: pattern.evidenceTerms as unknown as string[],
        fallbackValue: `text contains "${pattern.match}"`,
      });
      findings.push(
        makeFinding(
          input.filePath,
          "script_flags",
          "consent-bypass-cli-flag",
          `Consent bypass CLI flag detected: ${pattern.match}`,
          evidence,
        ),
      );
      break;
    }
  }

  return findings;
}
