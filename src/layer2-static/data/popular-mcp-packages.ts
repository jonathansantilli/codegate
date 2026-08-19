import { loadActiveContentBundle } from "../../content/content-store.js";

/**
 * Well-known MCP server packages used as the reference set for typosquat
 * detection. Curated, not exhaustive: entries should be packages an
 * attacker would plausibly imitate. Data-driven so the content feed can
 * extend it without a release.
 */
export const POPULAR_MCP_PACKAGES: Readonly<{ npm: readonly string[]; pypi: readonly string[] }> = {
  npm: [
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/inspector",
    "@anthropic/mcp-server-filesystem",
    "@playwright/mcp",
    "@browserbasehq/mcp",
    "@notionhq/notion-mcp-server",
    "@supabase/mcp-server-supabase",
    "@upstash/context7-mcp",
    "@21st-dev/magic",
    "@sentry/mcp-server",
    "@elastic/mcp-server-elasticsearch",
    "firecrawl-mcp",
    "tavily-mcp",
    "exa-mcp-server",
    "mcp-remote",
    "supergateway",
    "figma-developer-mcp",
    "chrome-devtools-mcp",
    "graphlit-mcp-server",
  ],
  pypi: [
    "mcp",
    "mcp-server-git",
    "mcp-server-fetch",
    "mcp-server-time",
    "mcp-server-sqlite",
    "mcp-server-sentry",
    "fastmcp",
    "mcp-atlassian",
    "awslabs.aws-documentation-mcp-server",
  ],
};

let cachedActivePackages: { npm: readonly string[]; pypi: readonly string[] } | null = null;

export function resetActivePopularMcpPackagesCache(): void {
  cachedActivePackages = null;
}

function feedList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0)
    : [];
}

/** Bundled popular packages plus any extras delivered by the verified content feed. */
export function activePopularMcpPackages(): { npm: readonly string[]; pypi: readonly string[] } {
  if (cachedActivePackages) {
    return cachedActivePackages;
  }
  let npmExtra: string[];
  let pypiExtra: string[];
  try {
    const bundle = loadActiveContentBundle();
    npmExtra = feedList(bundle?.popular_packages?.npm);
    pypiExtra = feedList(bundle?.popular_packages?.pypi);
  } catch {
    npmExtra = [];
    pypiExtra = [];
  }
  cachedActivePackages = {
    npm: [...new Set([...POPULAR_MCP_PACKAGES.npm, ...npmExtra])],
    pypi: [...new Set([...POPULAR_MCP_PACKAGES.pypi, ...pypiExtra])],
  };
  return cachedActivePackages;
}
