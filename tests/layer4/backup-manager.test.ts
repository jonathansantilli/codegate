import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const cleanupPaths: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "codegate-backup-manager-"));
  cleanupPaths.push(dir);
  return dir;
}

afterEach(() => {
  while (cleanupPaths.length > 0) {
    const next = cleanupPaths.pop();
    if (!next) {
      continue;
    }
    rmSync(next, { recursive: true, force: true });
  }
  vi.resetModules();
  vi.restoreAllMocks();
  vi.unmock("node:fs");
});

describe("backup manager", () => {
  it("skips files that disappear before their backup read completes", async () => {
    const root = makeTempDir();
    const targetFile = resolve(root, ".claude/settings.json");
    mkdirSync(resolve(root, ".claude"), { recursive: true });
    writeFileSync(targetFile, '{ "safe": true }\n', "utf8");

    vi.doMock("node:fs", async (importOriginal) => {
      const actual = await importOriginal<typeof import("node:fs")>();
      return {
        ...actual,
        readFileSync(path: Parameters<typeof actual.readFileSync>[0], options?: unknown) {
          if (path === targetFile) {
            const error = new Error(
              `ENOENT: no such file or directory, open '${targetFile}'`,
            ) as Error & { code?: string };
            error.code = "ENOENT";
            throw error;
          }
          return actual.readFileSync(path, options as never);
        },
      };
    });

    const { createBackupSession } = await import("../../src/layer4-remediation/backup-manager");
    const session = createBackupSession({
      projectRoot: root,
      version: "0.1.0",
      filePaths: [".claude/settings.json"],
    });

    expect(session.manifest.files).toEqual([]);
  });
});
