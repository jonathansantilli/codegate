export interface RemoveFieldResult<T> {
  value: T;
  changed: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cleanupEmptyParents(root: Record<string, unknown>, path: string[]): void {
  for (let index = path.length - 1; index > 0; index -= 1) {
    const parentPath = path.slice(0, index);
    const key = parentPath[parentPath.length - 1];
    const containerPath = parentPath.slice(0, -1);

    let container: Record<string, unknown> = root;
    for (const segment of containerPath) {
      const next = container[segment];
      if (!isRecord(next)) {
        return;
      }
      container = next;
    }

    const candidate = container[key];
    if (!isRecord(candidate)) {
      return;
    }
    if (Object.keys(candidate).length === 0) {
      delete container[key];
      continue;
    }
    return;
  }
}

export function removeField<T>(input: T, fieldPath: string): RemoveFieldResult<T> {
  if (!isRecord(input)) {
    return { value: input, changed: false };
  }
  const path = fieldPath.split(".").filter((segment) => segment.length > 0);
  if (path.length === 0) {
    return { value: input, changed: false };
  }

  const clone = structuredClone(input) as Record<string, unknown>;
  let current: Record<string, unknown> = clone;

  for (let index = 0; index < path.length - 1; index += 1) {
    const segment = path[index] as string;
    const next = current[segment];
    if (!isRecord(next)) {
      return { value: input, changed: false };
    }
    current = next;
  }

  const leaf = path[path.length - 1] as string;
  if (!(leaf in current)) {
    return { value: input, changed: false };
  }
  delete current[leaf];

  cleanupEmptyParents(clone, path);
  return { value: clone as T, changed: true };
}
