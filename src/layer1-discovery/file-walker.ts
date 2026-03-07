import { existsSync, readdirSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  "__pycache__",
  ".venv",
  "vendor",
  ".git/objects",
  ".git/refs",
]);

export interface WalkerOptions {
  maxDepth?: number;
}

export interface SymlinkEscape {
  path: string;
  target: string;
}

export interface WalkResult {
  files: string[];
  symlinkEscapes: SymlinkEscape[];
  circularSymlinks: string[];
}

function isOutsideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

function shouldSkipDirectory(relativePath: string): boolean {
  if (relativePath === ".git/hooks" || relativePath.startsWith(`.git/hooks${sep}`)) {
    return false;
  }
  if (relativePath === ".git" || relativePath.startsWith(`.git${sep}`)) {
    return true;
  }
  const normalized = relativePath.split(sep).join("/");
  return SKIP_DIRS.has(normalized) || SKIP_DIRS.has(normalized.split("/").at(-1) ?? normalized);
}

export function walkProjectTree(root: string, options: WalkerOptions = {}): WalkResult {
  const maxDepth = options.maxDepth ?? 5;
  const files: string[] = [];
  const symlinkEscapes: SymlinkEscape[] = [];
  const circularSymlinks: string[] = [];

  function walkDirectory(currentDir: string, depth: number): void {
    if (depth > maxDepth) {
      return;
    }

    const entries = readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      const relPath = relative(root, fullPath);

      if (entry.isSymbolicLink()) {
        try {
          const target = realpathSync(fullPath);
          if (isOutsideRoot(root, target)) {
            symlinkEscapes.push({ path: fullPath, target });
          }
        } catch (error) {
          const err = error as NodeJS.ErrnoException;
          if (err.code === "ELOOP") {
            circularSymlinks.push(fullPath);
          }
        }
        files.push(fullPath);
        continue;
      }

      if (entry.isDirectory()) {
        if (relPath === ".git") {
          const hooksDir = join(fullPath, "hooks");
          if (existsSync(hooksDir)) {
            walkDirectory(hooksDir, depth + 1);
          }
          continue;
        }
        if (shouldSkipDirectory(relPath)) {
          continue;
        }
        walkDirectory(fullPath, depth + 1);
        continue;
      }

      if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }

  walkDirectory(root, 0);
  return { files, symlinkEscapes, circularSymlinks };
}
