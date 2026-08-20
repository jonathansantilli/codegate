import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  addTrustedDirectory,
  listTrustedDirectories,
  removeTrustedDirectory,
  type TrustStoreDeps,
} from "../../src/commands/trust";

// Resolve fixture paths so expectations hold on Windows (drive-letter roots,
// backslash separators) as well as POSIX.
const HOME = resolve("/home/user");
const WORK = resolve("/work");
const PROJECT = resolve("/work/project");
const DIR_A = resolve("/a");
const DIR_B = resolve("/b");
const CONFIG_PATH = join(HOME, ".codegate", "config.json");

function makeMemoryStore(initial: Record<string, string> = {}): {
  deps: TrustStoreDeps;
  files: Map<string, string>;
} {
  const files = new Map<string, string>(Object.entries(initial));
  return {
    files,
    deps: {
      homeDir: () => HOME,
      pathExists: (path) => files.has(path),
      readFile: (path) => {
        const content = files.get(path);
        if (content === undefined) {
          throw new Error(`missing: ${path}`);
        }
        return content;
      },
      writeFile: (path, content) => {
        files.set(path, content);
      },
    },
  };
}

describe("trust command store", () => {
  it("adds a directory to a fresh global config", () => {
    const { deps, files } = makeMemoryStore();

    const result = addTrustedDirectory({ dir: "./project", cwd: WORK }, deps);

    expect(result.changed).toBe(true);
    expect(result.directory).toBe(PROJECT);
    expect(result.configPath).toBe(CONFIG_PATH);
    expect(JSON.parse(files.get(CONFIG_PATH) ?? "{}")).toEqual({
      trusted_directories: [PROJECT],
    });
  });

  it("is idempotent for already-trusted directories", () => {
    const { deps } = makeMemoryStore({
      [CONFIG_PATH]: JSON.stringify({ trusted_directories: [PROJECT] }),
    });

    const result = addTrustedDirectory({ dir: PROJECT, cwd: WORK }, deps);

    expect(result.changed).toBe(false);
    expect(result.trustedDirectories).toEqual([PROJECT]);
  });

  it("preserves unrelated config keys when writing", () => {
    const { deps, files } = makeMemoryStore({
      [CONFIG_PATH]: JSON.stringify({ severity_threshold: "medium" }),
    });

    addTrustedDirectory({ dir: PROJECT, cwd: WORK }, deps);

    expect(JSON.parse(files.get(CONFIG_PATH) ?? "{}")).toEqual({
      severity_threshold: "medium",
      trusted_directories: [PROJECT],
    });
  });

  it("lists trusted directories", () => {
    const { deps } = makeMemoryStore({
      [CONFIG_PATH]: JSON.stringify({ trusted_directories: [DIR_A, DIR_B] }),
    });

    const listed = listTrustedDirectories({}, deps);

    expect(listed.trustedDirectories).toEqual([DIR_A, DIR_B]);
  });

  it("removes a trusted directory and reports no-ops", () => {
    const { deps, files } = makeMemoryStore({
      [CONFIG_PATH]: JSON.stringify({ trusted_directories: [DIR_A, DIR_B] }),
    });

    const removed = removeTrustedDirectory({ dir: DIR_A, cwd: WORK }, deps);
    expect(removed.changed).toBe(true);
    expect(JSON.parse(files.get(CONFIG_PATH) ?? "{}")).toEqual({
      trusted_directories: [DIR_B],
    });

    const noop = removeTrustedDirectory({ dir: resolve("/missing"), cwd: WORK }, deps);
    expect(noop.changed).toBe(false);
  });

  it("supports a custom config path", () => {
    const { deps, files } = makeMemoryStore();

    const result = addTrustedDirectory(
      { dir: PROJECT, cwd: WORK, configPath: "/custom/config.json" },
      deps,
    );

    expect(result.configPath).toBe("/custom/config.json");
    expect(files.has("/custom/config.json")).toBe(true);
  });
});
