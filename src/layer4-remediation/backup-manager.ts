import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

export interface BackupManifestEntry {
  path: string;
  sha256: string;
  size: number;
}

export interface BackupManifest {
  codegate_version: string;
  created_at: string;
  files: BackupManifestEntry[];
}

export interface BackupSession {
  sessionId: string;
  sessionDir: string;
  manifestPath: string;
  manifest: BackupManifest;
}

export interface CreateBackupSessionInput {
  projectRoot: string;
  version: string;
  filePaths: string[];
}

export interface RestoreBackupSessionInput {
  projectRoot: string;
  sessionId: string;
}

export interface RestoreBackupSessionResult {
  restoredFiles: number;
  sessionId: string;
}

function safeRelativePath(filePath: string): string {
  if (isAbsolute(filePath)) {
    throw new Error(`Backup path must be relative: ${filePath}`);
  }
  if (filePath.includes("..")) {
    throw new Error(`Backup path traversal is not allowed: ${filePath}`);
  }
  return filePath;
}

function hashContent(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

function ensureParentDirectory(path: string): void {
  mkdirSync(dirname(path), { recursive: true });
}

function backupRoot(projectRoot: string): string {
  return resolve(projectRoot, ".codegate-backup");
}

function sessionIdFromNow(): string {
  const stamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
  const nonce = randomBytes(3).toString("hex");
  return `${stamp}-${nonce}`;
}

function manifestForSession(sessionDir: string): string {
  return join(sessionDir, ".manifest.json");
}

export function createBackupSession(input: CreateBackupSessionInput): BackupSession {
  const sessionId = sessionIdFromNow();
  const root = backupRoot(input.projectRoot);
  const sessionDir = join(root, sessionId);
  mkdirSync(sessionDir, { recursive: true });

  const entries: BackupManifestEntry[] = [];

  for (const filePath of input.filePaths) {
    const relativePath = safeRelativePath(filePath);
    const sourcePath = resolve(input.projectRoot, relativePath);
    if (!existsSync(sourcePath) || !statSync(sourcePath).isFile()) {
      continue;
    }
    const content = readFileSync(sourcePath, "utf8");
    const destinationPath = resolve(sessionDir, relativePath);
    ensureParentDirectory(destinationPath);
    writeFileSync(destinationPath, content, "utf8");
    entries.push({
      path: relativePath,
      sha256: hashContent(content),
      size: Buffer.byteLength(content, "utf8"),
    });
  }

  const manifest: BackupManifest = {
    codegate_version: input.version,
    created_at: new Date().toISOString(),
    files: entries,
  };
  const manifestPath = manifestForSession(sessionDir);
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf8");

  return {
    sessionId,
    sessionDir,
    manifestPath,
    manifest,
  };
}

export function listBackupSessions(projectRoot: string): string[] {
  const root = backupRoot(projectRoot);
  if (!existsSync(root)) {
    return [];
  }

  return readdirSync(root)
    .filter((entry) => entry !== "quarantine")
    .filter((entry) => {
      const fullPath = join(root, entry);
      return statSync(fullPath).isDirectory();
    })
    .sort()
    .reverse();
}

function readManifest(projectRoot: string, sessionId: string): BackupManifest {
  const sessionDir = join(backupRoot(projectRoot), sessionId);
  const manifestPath = manifestForSession(sessionDir);
  if (!existsSync(manifestPath)) {
    throw new Error(`Backup manifest missing for session ${sessionId}`);
  }

  const raw = readFileSync(manifestPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Invalid backup manifest for session ${sessionId}`);
  }

  const manifest = parsed as BackupManifest;
  if (!Array.isArray(manifest.files)) {
    throw new Error(`Invalid backup manifest for session ${sessionId}`);
  }
  return manifest;
}

export function restoreBackupSession(input: RestoreBackupSessionInput): RestoreBackupSessionResult {
  const sessionDir = join(backupRoot(input.projectRoot), input.sessionId);
  const manifest = readManifest(input.projectRoot, input.sessionId);

  for (const entry of manifest.files) {
    const backupPath = resolve(sessionDir, safeRelativePath(entry.path));
    if (!existsSync(backupPath)) {
      throw new Error(`Backup file missing: ${entry.path}`);
    }
    const content = readFileSync(backupPath, "utf8");
    const actualHash = hashContent(content);
    if (actualHash !== entry.sha256) {
      throw new Error(`Backup manifest hash mismatch for ${entry.path}`);
    }
  }

  for (const entry of manifest.files) {
    const backupPath = resolve(sessionDir, safeRelativePath(entry.path));
    const targetPath = resolve(input.projectRoot, safeRelativePath(entry.path));
    const content = readFileSync(backupPath, "utf8");
    ensureParentDirectory(targetPath);
    writeFileSync(targetPath, content, "utf8");
  }

  rmSync(sessionDir, { recursive: true, force: true });
  return {
    restoredFiles: manifest.files.length,
    sessionId: input.sessionId,
  };
}
