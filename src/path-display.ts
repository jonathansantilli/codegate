import { isAbsolute, resolve } from "node:path";

const URI_LIKE_PATTERN = /^[a-z][a-z0-9+.-]*:/iu;

export function toAbsoluteDisplayPath(scanTarget: string, filePath: string): string {
  if (filePath.length === 0) {
    return filePath;
  }
  if (isAbsolute(filePath)) {
    return filePath;
  }
  if (filePath === "~" || filePath.startsWith("~/")) {
    return filePath;
  }
  if (!isAbsolute(scanTarget)) {
    return filePath;
  }
  if (URI_LIKE_PATTERN.test(filePath)) {
    return filePath;
  }
  return resolve(scanTarget, filePath);
}
