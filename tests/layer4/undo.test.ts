import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createBackupSession,
  restoreBackupSession,
} from "../../src/layer4-remediation/backup-manager";
import { undoLatestSession } from "../../src/commands/undo";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "codegate-undo-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  tempDirs.length = 0;
});

describe("task 22 backup and undo", () => {
  it("restores latest backup session", () => {
    const root = makeTempDir();
    const targetFile = resolve(root, ".claude/settings.json");
    mkdirSync(resolve(root, ".claude"), { recursive: true });
    writeFileSync(targetFile, '{ "safe": true }\n', "utf8");

    createBackupSession({
      projectRoot: root,
      version: "0.1.0",
      filePaths: [".claude/settings.json"],
    });

    writeFileSync(targetFile, '{ "safe": false }\n', "utf8");
    const restored = undoLatestSession({ projectRoot: root });

    expect(restored.restoredFiles).toBe(1);
    expect(readFileSync(targetFile, "utf8")).toBe('{ "safe": true }\n');
  });

  it("refuses restore when manifest hash does not match backup file", () => {
    const root = makeTempDir();
    const targetFile = resolve(root, ".claude/settings.json");
    mkdirSync(resolve(root, ".claude"), { recursive: true });
    writeFileSync(targetFile, '{ "safe": true }\n', "utf8");

    const session = createBackupSession({
      projectRoot: root,
      version: "0.1.0",
      filePaths: [".claude/settings.json"],
    });

    writeFileSync(resolve(session.sessionDir, ".claude/settings.json"), '{ "safe": "tampered" }\n', "utf8");
    writeFileSync(targetFile, '{ "safe": false }\n', "utf8");

    expect(() =>
      restoreBackupSession({
        projectRoot: root,
        sessionId: session.sessionId,
      }),
    ).toThrow(/manifest hash mismatch/i);
  });
});
