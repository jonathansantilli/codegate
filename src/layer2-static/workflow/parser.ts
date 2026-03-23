import type { WorkflowFacts, WorkflowJobFacts, WorkflowStepFacts } from "./types.js";

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function toStringMap(value: unknown): Record<string, string> | undefined {
  const record = asRecord(value);
  if (!record) {
    return undefined;
  }

  const entries: Record<string, string> = {};
  for (const [key, entry] of Object.entries(record)) {
    if (typeof entry === "string") {
      entries[key] = entry;
    }
  }

  return Object.keys(entries).length > 0 ? entries : undefined;
}

function extractNeeds(value: unknown): string[] {
  if (typeof value === "string") {
    const normalized = value.trim();
    return normalized.length > 0 ? [normalized] : [];
  }

  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(
    (entry): entry is string => typeof entry === "string" && entry.trim().length > 0,
  );
}

function normalizeWorkflowPath(value: string): string {
  return value.replaceAll("\\", "/");
}

export function isGitHubWorkflowPath(path: string): boolean {
  return /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/iu.test(normalizeWorkflowPath(path));
}

function extractTriggers(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === "string");
  }

  const record = asRecord(value);
  if (!record) {
    return [];
  }

  return Object.keys(record);
}

function extractStepFacts(step: unknown): WorkflowStepFacts | null {
  const stepRecord = asRecord(step);
  if (!stepRecord) {
    return null;
  }

  const stepFacts: WorkflowStepFacts = {
    if: asString(stepRecord.if),
    uses: asString(stepRecord.uses),
    run: asString(stepRecord.run),
    with: toStringMap(stepRecord.with),
  };

  if (!stepFacts.uses && !stepFacts.run) {
    return null;
  }

  return stepFacts;
}

function extractJobFacts(id: string, value: unknown): WorkflowJobFacts | null {
  const jobRecord = asRecord(value);
  if (!jobRecord) {
    return null;
  }

  const stepsRaw = Array.isArray(jobRecord.steps) ? jobRecord.steps : [];
  const steps = stepsRaw
    .map((step) => extractStepFacts(step))
    .filter((step): step is WorkflowStepFacts => step !== null);

  return {
    id,
    if: asString(jobRecord.if),
    uses: asString(jobRecord.uses),
    with: toStringMap(jobRecord.with),
    needs: extractNeeds(jobRecord.needs),
    secrets: jobRecord.secrets,
    permissions: jobRecord.permissions,
    steps,
  };
}

export function extractWorkflowFacts(parsed: unknown): WorkflowFacts | null {
  const root = asRecord(parsed);
  if (!root) {
    return null;
  }

  const triggers = extractTriggers(root.on);
  const jobsRecord = asRecord(root.jobs);
  const jobs: WorkflowJobFacts[] = jobsRecord
    ? Object.entries(jobsRecord)
        .map(([id, value]) => extractJobFacts(id, value))
        .filter((job): job is WorkflowJobFacts => job !== null)
    : [];

  if (triggers.length === 0 && jobs.length === 0) {
    return null;
  }

  return {
    triggers,
    workflowPermissions: root.permissions,
    jobs,
  };
}
