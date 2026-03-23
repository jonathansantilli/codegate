import type {
  ActionFacts,
  ActionInputFacts,
  ActionOutputFacts,
  ActionRunsFacts,
  ActionStepFacts,
} from "./types.js";

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asStringRecord(value: unknown): Record<string, string> | undefined {
  const record = asRecord(value);
  if (!record) {
    return undefined;
  }

  const result: Record<string, string> = {};
  for (const [key, entry] of Object.entries(record)) {
    if (typeof entry === "string") {
      result[key] = entry;
    }
  }

  return Object.keys(result).length > 0 ? result : undefined;
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const result = value.filter((entry): entry is string => typeof entry === "string");
  return result.length > 0 ? result : undefined;
}

function normalizeActionPath(value: string): string {
  return value.replaceAll("\\", "/");
}

export function isGitHubActionPath(path: string): boolean {
  return /(?:^|\/)action\.ya?ml$/iu.test(normalizeActionPath(path));
}

function extractStepFacts(step: unknown): ActionStepFacts | null {
  const stepRecord = asRecord(step);
  if (!stepRecord) {
    return null;
  }

  const withEntries = asStringRecord(stepRecord.with);
  const envEntries = asStringRecord(stepRecord.env);
  const stepFacts: ActionStepFacts = {
    id: asString(stepRecord.id),
    name: asString(stepRecord.name),
    uses: asString(stepRecord.uses),
    run: asString(stepRecord.run),
    if: asString(stepRecord.if),
    shell: asString(stepRecord.shell),
    workingDirectory:
      asString(stepRecord["working-directory"]) ?? asString(stepRecord.workingDirectory),
    with: withEntries,
    env: envEntries,
  };

  if (!stepFacts.uses && !stepFacts.run) {
    return null;
  }

  return stepFacts;
}

function extractInputs(value: unknown): Record<string, ActionInputFacts> | undefined {
  const inputs = asRecord(value);
  if (!inputs) {
    return undefined;
  }

  const result: Record<string, ActionInputFacts> = {};
  for (const [name, inputValue] of Object.entries(inputs)) {
    const inputRecord = asRecord(inputValue);
    if (!inputRecord) {
      continue;
    }

    const entry: ActionInputFacts = {
      description: asString(inputRecord.description),
      required: asBoolean(inputRecord.required),
      default: asString(inputRecord.default),
      deprecationMessage:
        asString(inputRecord.deprecationMessage) ?? asString(inputRecord.deprecation_message),
    };

    if (
      entry.description !== undefined ||
      entry.required !== undefined ||
      entry.default !== undefined ||
      entry.deprecationMessage !== undefined
    ) {
      result[name] = entry;
    }
  }

  return Object.keys(result).length > 0 ? result : undefined;
}

function extractOutputs(value: unknown): Record<string, ActionOutputFacts> | undefined {
  const outputs = asRecord(value);
  if (!outputs) {
    return undefined;
  }

  const result: Record<string, ActionOutputFacts> = {};
  for (const [name, outputValue] of Object.entries(outputs)) {
    const outputRecord = asRecord(outputValue);
    if (!outputRecord) {
      continue;
    }

    const entry: ActionOutputFacts = {
      description: asString(outputRecord.description),
      value: asString(outputRecord.value),
    };

    if (entry.description !== undefined || entry.value !== undefined) {
      result[name] = entry;
    }
  }

  return Object.keys(result).length > 0 ? result : undefined;
}

function extractRuns(value: unknown): ActionRunsFacts | undefined {
  const runs = asRecord(value);
  if (!runs) {
    return undefined;
  }

  const stepsRaw = Array.isArray(runs.steps) ? runs.steps : [];
  const steps = stepsRaw
    .map((step) => extractStepFacts(step))
    .filter((step): step is ActionStepFacts => step !== null);

  const result: ActionRunsFacts = {
    using: asString(runs.using),
    main: asString(runs.main),
    pre: asString(runs.pre),
    post: asString(runs.post),
    image: asString(runs.image),
    args: asStringArray(runs.args),
    steps: steps.length > 0 ? steps : undefined,
  };

  if (
    result.using === undefined &&
    result.main === undefined &&
    result.pre === undefined &&
    result.post === undefined &&
    result.image === undefined &&
    result.args === undefined &&
    result.steps === undefined
  ) {
    return undefined;
  }

  return result;
}

export function extractActionFacts(parsed: unknown): ActionFacts | null {
  const root = asRecord(parsed);
  if (!root) {
    return null;
  }

  const runs = extractRuns(root.runs);
  const inputs = extractInputs(root.inputs);
  const outputs = extractOutputs(root.outputs);
  const branding = asRecord(root.branding) ?? undefined;

  if (
    runs === undefined &&
    inputs === undefined &&
    outputs === undefined &&
    branding === undefined &&
    asString(root.name) === undefined &&
    asString(root.description) === undefined &&
    asString(root.author) === undefined
  ) {
    return null;
  }

  return {
    name: asString(root.name),
    description: asString(root.description),
    author: asString(root.author),
    branding,
    inputs,
    outputs,
    runs,
  };
}
