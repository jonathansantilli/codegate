import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";

export interface EnvOverrideInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  trustedApiDomains: string[];
}

const CRITICAL_KEYS = new Set([
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_BEDROCK_BASE_URL",
  "ANTHROPIC_VERTEX_BASE_URL",
  "OPENAI_BASE_URL",
  "OPENAI_API_BASE",
  "CODEX_HOME",
]);

const HEADER_KEYS = new Set(["ANTHROPIC_CUSTOM_HEADERS"]);

const API_KEY_KEYS = new Set([
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "AZURE_OPENAI_API_KEY",
  "GOOGLE_AI_API_KEY",
  "DEEPSEEK_API_KEY",
]);

function getEnvRecord(parsed: unknown): Record<string, unknown> {
  if (!parsed || typeof parsed !== "object") {
    return {};
  }
  const root = parsed as Record<string, unknown>;
  if (root.env && typeof root.env === "object") {
    return root.env as Record<string, unknown>;
  }
  return root;
}

function isTrustedHost(hostname: string, trustedApiDomains: string[]): boolean {
  if (hostname === "api.anthropic.com" || hostname.endsWith(".anthropic.com")) {
    return true;
  }
  if (hostname === "api.openai.com" || hostname.endsWith(".openai.azure.com")) {
    return true;
  }
  if (hostname.endsWith(".amazonaws.com")) {
    return true;
  }
  if (hostname.endsWith(".googleapis.com")) {
    return true;
  }

  return trustedApiDomains.some((domain) => {
    if (domain.startsWith("*.")) {
      return hostname.endsWith(domain.slice(1));
    }
    return hostname === domain;
  });
}

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
    finding_id: `ENV_OVERRIDE-${filePath}-${field}`,
    severity,
    category: "ENV_OVERRIDE",
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
    owasp: ["ASI03", "ASI06"],
    cwe: "CWE-522",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field", "replace_with_default"],
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

export function detectEnvOverrides(input: EnvOverrideInput): Finding[] {
  const root =
    input.parsed && typeof input.parsed === "object"
      ? (input.parsed as Record<string, unknown>)
      : null;
  const hasEnvObject = !!(root && root.env && typeof root.env === "object");
  const env = getEnvRecord(input.parsed);
  const findings: Finding[] = [];

  for (const [key, rawValue] of Object.entries(env)) {
    if (typeof rawValue !== "string") {
      continue;
    }

    const field = `env.${key}`;
    const evidence = buildFindingEvidence({
      textContent: input.textContent,
      jsonPaths: hasEnvObject ? [field] : [key, field],
      searchTerms: [`"${key}"`, rawValue],
      fallbackValue: `${field} = ${rawValue}`,
    });

    if (HEADER_KEYS.has(key) || key.endsWith("_CUSTOM_HEADERS") || key.endsWith("_EXTRA_HEADERS")) {
      findings.push(
        makeFinding(
          input.filePath,
          field,
          "env-custom-headers-override",
          "HIGH",
          `${key} injects custom API headers`,
          evidence,
        ),
      );
      continue;
    }

    if (API_KEY_KEYS.has(key)) {
      findings.push(
        makeFinding(
          input.filePath,
          field,
          "env-api-key-override",
          "MEDIUM",
          `${key} overrides AI tool credentials at project scope`,
          evidence,
        ),
      );
      continue;
    }

    const looksLikeEndpoint =
      CRITICAL_KEYS.has(key) ||
      key.endsWith("_BASE_URL") ||
      key.endsWith("_API_URL") ||
      key.endsWith("_ENDPOINT");
    if (!looksLikeEndpoint) {
      continue;
    }

    try {
      const url = new URL(rawValue);
      if (url.hostname === "localhost" || url.hostname === "127.0.0.1") {
        findings.push(
          makeFinding(
            input.filePath,
            field,
            "env-local-endpoint-override",
            "MEDIUM",
            `${key} points to localhost/loopback and may intercept API traffic`,
            evidence,
          ),
        );
        continue;
      }
      if (isTrustedHost(url.hostname, input.trustedApiDomains)) {
        continue;
      }

      findings.push(
        makeFinding(
          input.filePath,
          field,
          "env-base-url-override",
          "CRITICAL",
          `${key} redirects API traffic to an untrusted domain`,
          evidence,
        ),
      );
    } catch {
      findings.push(
        makeFinding(
          input.filePath,
          field,
          "env-invalid-endpoint-override",
          "CRITICAL",
          `${key} contains an invalid endpoint override`,
          evidence,
        ),
      );
    }
  }

  return findings;
}
