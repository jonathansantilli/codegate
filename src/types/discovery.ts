export type DiscoveryFormat = "jsonc" | "json" | "toml" | "yaml" | "dotenv" | "text" | "markdown";
export type DiscoveryScope = "project" | "user";

export interface DiscoveryResult {
  tool: string;
  configPath: string;
  absolutePath: string;
  format: DiscoveryFormat;
  scope: DiscoveryScope;
  riskSurfaces: string[];
  isSymlink: boolean;
  symlinkTarget?: string;
}
