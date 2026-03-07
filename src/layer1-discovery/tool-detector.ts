import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { homedir as osHomedir } from "node:os";
import { join } from "node:path";
import which from "which";

export type ToolName =
  | "claude-code"
  | "codex-cli"
  | "opencode"
  | "cursor"
  | "windsurf"
  | "github-copilot"
  | "kiro"
  | "vscode"
  | "jetbrains";

export interface ToolDetection {
  tool: ToolName;
  installed: boolean;
  version: string | null;
  path: string | null;
  source: "path" | "app-bundle" | "extension" | "none";
}

export interface ToolDetectorDeps {
  platform: NodeJS.Platform;
  homedir: string;
  which: (binary: string) => string | undefined;
  execVersion: (binary: string) => string | null;
  pathExists: (path: string) => boolean;
  listDirectory: (path: string) => string[];
}

export interface ToolDetectorOptions {
  includeVersions?: boolean;
}

const defaultDeps: ToolDetectorDeps = {
  platform: process.platform,
  homedir: osHomedir(),
  which: (binary) => which.sync(binary, { nothrow: true }) ?? undefined,
  execVersion: (binary) => {
    const result = spawnSync(binary, ["--version"], { encoding: "utf8" });
    if (result.status !== 0) {
      return null;
    }
    const output = `${result.stdout ?? ""}`.trim();
    return output.length > 0 ? output.split(/\s+/u).pop() ?? output : null;
  },
  pathExists: (path) => existsSync(path),
  listDirectory: (path) => {
    try {
      return readdirSync(path);
    } catch {
      return [];
    }
  },
};

function appCandidates(tool: ToolName, platform: NodeJS.Platform, home: string): string[] {
  if (tool === "cursor") {
    if (platform === "darwin") return ["/Applications/Cursor.app"];
    if (platform === "linux") return [join(home, ".local/share/cursor"), "/opt/cursor"];
    return [join(home, "AppData/Local/Programs/Cursor")];
  }
  if (tool === "windsurf") {
    if (platform === "darwin") return ["/Applications/Windsurf.app"];
    if (platform === "linux") return [join(home, ".local/share/windsurf"), "/opt/windsurf"];
    return [join(home, "AppData/Local/Programs/Windsurf")];
  }
  if (tool === "kiro") {
    if (platform === "darwin") return ["/Applications/Kiro.app"];
    if (platform === "linux") return [join(home, ".local/share/kiro"), "/opt/kiro"];
    return [join(home, "AppData/Local/Programs/Kiro")];
  }
  if (tool === "jetbrains") {
    if (platform === "darwin") {
      return [
        "/Applications/JetBrains Toolbox/JetBrains Toolbox.app",
        join(home, "Library/Application Support/JetBrains/Toolbox/apps"),
        "/Applications/IntelliJ IDEA.app",
        "/Applications/WebStorm.app",
        "/Applications/PyCharm.app",
      ];
    }
    if (platform === "linux") {
      return [join(home, ".local/share/JetBrains/Toolbox/apps"), "/opt/jetbrains-toolbox/apps"];
    }
    return [
      join(home, "AppData/Local/JetBrains/Toolbox/apps"),
      join(home, "AppData/Roaming/JetBrains/Toolbox/apps"),
    ];
  }
  return [];
}

function detectCopilot(deps: ToolDetectorDeps): ToolDetection {
  const extensionsDir = join(deps.homedir, ".vscode/extensions");
  const entries = deps.listDirectory(extensionsDir);
  const copilot = entries.find((entry) => entry.startsWith("github.copilot-"));
  if (!copilot) {
    return {
      tool: "github-copilot",
      installed: false,
      version: null,
      path: null,
      source: "none",
    };
  }
  const version = copilot.split("github.copilot-")[1] ?? null;
  return {
    tool: "github-copilot",
    installed: true,
    version,
    path: join(extensionsDir, copilot),
    source: "extension",
  };
}

function detectCliOrAppTool(
  tool: ToolName,
  binary: string | null,
  deps: ToolDetectorDeps,
  options: ToolDetectorOptions,
): ToolDetection {
  if (binary) {
    const resolved = deps.which(binary);
    if (resolved) {
      return {
        tool,
        installed: true,
        version: options.includeVersions === false ? null : deps.execVersion(binary),
        path: resolved,
        source: "path",
      };
    }
  }

  for (const candidate of appCandidates(tool, deps.platform, deps.homedir)) {
    if (deps.pathExists(candidate)) {
      return {
        tool,
        installed: true,
        version: null,
        path: candidate,
        source: "app-bundle",
      };
    }
  }

  return {
    tool,
    installed: false,
    version: null,
    path: null,
    source: "none",
  };
}

export function detectTools(
  customDeps: ToolDetectorDeps = defaultDeps,
  options: ToolDetectorOptions = {},
): ToolDetection[] {
  const mappings: Array<{ tool: ToolName; binary: string | null }> = [
    { tool: "claude-code", binary: "claude" },
    { tool: "codex-cli", binary: "codex" },
    { tool: "opencode", binary: "opencode" },
    { tool: "cursor", binary: "cursor" },
    { tool: "windsurf", binary: "windsurf" },
    { tool: "kiro", binary: "kiro" },
    { tool: "vscode", binary: "code" },
    { tool: "jetbrains", binary: "idea" },
  ];

  const detections = mappings.map((entry) =>
    detectCliOrAppTool(entry.tool, entry.binary, customDeps, options),
  );
  detections.push(detectCopilot(customDeps));
  return detections;
}
