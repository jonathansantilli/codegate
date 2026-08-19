import { homedir } from "node:os";
import { isAbsolute, relative, resolve, sep } from "node:path";

export function expandHomePath(path: string): string {
  if (path === "~") {
    return homedir();
  }
  if (path.startsWith(`~${sep}`) || path.startsWith("~/")) {
    return resolve(homedir(), path.slice(2));
  }
  return path;
}

export function isTrustedDirectory(target: string, trustedDirectories: string[]): boolean {
  const resolvedTarget = resolve(target);

  return trustedDirectories.some((trustedPath) => {
    const resolvedTrusted = resolve(expandHomePath(trustedPath));
    const rel = relative(resolvedTrusted, resolvedTarget);
    return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
  });
}
