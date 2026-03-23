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

  const withValues = asRecord(stepRecord.with);
  const withEntries: Record<string, string> = {};
  if (withValues) {
    for (const [key, value] of Object.entries(withValues)) {
      if (typeof value === "string") {
        withEntries[key] = value;
      }
    }
  }

  const stepFacts: WorkflowStepFacts = {
    uses: asString(stepRecord.uses),
    run: asString(stepRecord.run),
    with: Object.keys(withEntries).length > 0 ? withEntries : undefined,
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
