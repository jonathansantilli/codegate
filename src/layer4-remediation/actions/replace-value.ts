export interface ReplaceValueResult<T> {
  value: T;
  changed: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function replaceValue<T>(
  input: T,
  fieldPath: string,
  nextValue: unknown,
): ReplaceValueResult<T> {
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
      current[segment] = {};
    }
    current = current[segment] as Record<string, unknown>;
  }

  const leaf = path[path.length - 1] as string;
  const previous = current[leaf];
  current[leaf] = nextValue;
  return { value: clone as T, changed: previous !== nextValue };
}
