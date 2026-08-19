/**
 * Well-known MCP server packages used as the reference set for typosquat
 * detection. Curated, not exhaustive: entries should be packages an
 * attacker would plausibly imitate. Data-driven so a content feed can
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
