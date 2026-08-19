import { describe, expect, it } from "vitest";
import {
  addTrustedDirectory,
  listTrustedDirectories,
  removeTrustedDirectory,
  type TrustStoreDeps,
} from "../../src/commands/trust";

function makeMemoryStore(initial: Record<string, string> = {}): {
  deps: TrustStoreDeps;
  files: Map<string, string>;
} {
  const files = new Map<string, string>(Object.entries(initial));
  return {
    files,
    deps: {
      homeDir: () => "/home/user",
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

const CONFIG_PATH = "/home/user/.codegate/config.json";

describe("trust command store", () => {
  it("adds a directory to a fresh global config", () => {
    const { deps, files } = makeMemoryStore();

    const result = addTrustedDirectory({ dir: "./project", cwd: "/work" }, deps);

    expect(result.changed).toBe(true);
    expect(result.directory).toBe("/work/project");
    expect(result.configPath).toBe(CONFIG_PATH);
    expect(JSON.parse(files.get(CONFIG_PATH) ?? "{}")).toEqual({
      trusted_directories: ["/work/project"],
    });
  });

  it("is idempotent for already-trusted directories", () => {
    const { deps } = makeMemoryStore({
      [CONFIG_PATH]: JSON.stringify({ trusted_directories: ["/work/project"] }),
    });

    const result = addTrustedDirectory({ dir: "/work/project", cwd: "/work" }, deps);

    expect(result.changed).toBe(false);
    expect(result.trustedDirectories).toEqual(["/work/project"]);
  });

  it("preserves unrelated config keys when writing", () => {
    const { deps, files } = makeMemoryStore({
      [CONFIG_PATH]: JSON.stringify({ severity_threshold: "medium" }),
    });

    addTrustedDirectory({ dir: "/work/project", cwd: "/work" }, deps);

    expect(JSON.parse(files.get(CONFIG_PATH) ?? "{}")).toEqual({
      severity_threshold: "medium",
      trusted_directories: ["/work/project"],
    });
  });

  it("lists trusted directories", () => {
    const { deps } = makeMemoryStore({
      [CONFIG_PATH]: JSON.stringify({ trusted_directories: ["/a", "/b"] }),
    });

    const listed = listTrustedDirectories({}, deps);

    expect(listed.trustedDirectories).toEqual(["/a", "/b"]);
  });

  it("removes a trusted directory and reports no-ops", () => {
    const { deps, files } = makeMemoryStore({
      [CONFIG_PATH]: JSON.stringify({ trusted_directories: ["/a", "/b"] }),
    });

    const removed = removeTrustedDirectory({ dir: "/a", cwd: "/work" }, deps);
    expect(removed.changed).toBe(true);
    expect(JSON.parse(files.get(CONFIG_PATH) ?? "{}")).toEqual({
      trusted_directories: ["/b"],
    });

    const noop = removeTrustedDirectory({ dir: "/missing", cwd: "/work" }, deps);
    expect(noop.changed).toBe(false);
  });

  it("supports a custom config path", () => {
    const { deps, files } = makeMemoryStore();

    const result = addTrustedDirectory(
      { dir: "/work/project", cwd: "/work", configPath: "/custom/config.json" },
      deps,
    );

    expect(result.configPath).toBe("/custom/config.json");
    expect(files.has("/custom/config.json")).toBe(true);
  });
});
