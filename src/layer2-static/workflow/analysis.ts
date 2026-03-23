import type { WorkflowFacts } from "./types.js";

const UNTRUSTED_TRIGGER_SET = new Set([
  "pull_request",
  "pull_request_target",
  "workflow_run",
  "issue_comment",
  "pull_request_review_comment",
  "discussion_comment",
]);

const BOT_ONLY_CONDITION_PATTERNS = [
  /github\.actor\s*==\s*['"]dependabot\[bot\]['"]/iu,
  /github\.actor\s*==\s*['"]github-actions\[bot\]['"]/iu,
  /github\.event\.pull_request\.head\.repo\.fork\s*==\s*false/iu,
];

const UPLOAD_ARTIFACT_ACTIONS = new Set([
  "actions/upload-artifact",
  "actions/upload-artifact/merge",
]);

const DOWNLOAD_ARTIFACT_ACTIONS = new Set(["actions/download-artifact"]);

export interface WorkflowArtifactTransferEdge {
  artifactName: string;
  producerJobId: string;
  producerStepIndex: number;
  consumerJobId: string;
  consumerStepIndex: number;
  consumerDownloadsAll: boolean;
}

export interface WorkflowCallBoundaryContext {
  hasWorkflowCall: boolean;
  declaredInputKeys: string[];
  requiredInputKeys: string[];
  declaredSecretKeys: string[];
  requiredSecretKeys: string[];
  jobsWithInheritedSecrets: string[];
  jobsCallingReusableWorkflow: string[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function normalizeUses(uses: string | undefined): string | null {
  if (!uses) {
    return null;
  }
  const trimmed = uses.trim().toLowerCase();
  if (trimmed.length === 0) {
    return null;
  }
  const atIndex = trimmed.indexOf("@");
  if (atIndex === -1) {
    return trimmed;
  }
  return trimmed.slice(0, atIndex);
}

function isWorkflowTriggerUntrusted(trigger: string): boolean {
  return UNTRUSTED_TRIGGER_SET.has(trigger.trim().toLowerCase());
}

function isUntrustedRestrictedCondition(condition: string | undefined): boolean {
  if (!condition) {
    return false;
  }
  return BOT_ONLY_CONDITION_PATTERNS.some((pattern) => pattern.test(condition));
}

function normalizeArtifactName(value: string | undefined): string | null {
  if (!value) {
    return null;
  }
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : null;
}

export function buildWorkflowNeedsGraph(facts: WorkflowFacts): Map<string, string[]> {
  return new Map(facts.jobs.map((job) => [job.id, [...job.needs]]));
}

export function collectTransitiveDependencies(
  facts: WorkflowFacts,
  seedJobIds: Iterable<string>,
): Set<string> {
  const graph = buildWorkflowNeedsGraph(facts);
  const visited = new Set<string>();
  const queue = [...seedJobIds];

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      continue;
    }
    const dependencies = graph.get(current) ?? [];
    for (const dependency of dependencies) {
      if (visited.has(dependency)) {
        continue;
      }
      visited.add(dependency);
      queue.push(dependency);
    }
  }

  return visited;
}

export function collectTransitiveDependents(
  facts: WorkflowFacts,
  seedJobIds: Iterable<string>,
): Set<string> {
  const reverseGraph = new Map<string, string[]>();
  for (const job of facts.jobs) {
    for (const dependency of job.needs) {
      const dependents = reverseGraph.get(dependency) ?? [];
      dependents.push(job.id);
      reverseGraph.set(dependency, dependents);
    }
  }

  const visited = new Set<string>();
  const queue = [...seedJobIds];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      continue;
    }
    const dependents = reverseGraph.get(current) ?? [];
    for (const dependent of dependents) {
      if (visited.has(dependent)) {
        continue;
      }
      visited.add(dependent);
      queue.push(dependent);
    }
  }
  return visited;
}

export function collectArtifactTransferEdges(facts: WorkflowFacts): WorkflowArtifactTransferEdge[] {
  const producersByArtifact = new Map<string, Array<{ jobId: string; stepIndex: number }>>();

  const edges: WorkflowArtifactTransferEdge[] = [];
  const dedupe = new Set<string>();

  for (const job of facts.jobs) {
    for (const [stepIndex, step] of job.steps.entries()) {
      const normalizedUses = normalizeUses(step.uses);
      if (!normalizedUses || !UPLOAD_ARTIFACT_ACTIONS.has(normalizedUses)) {
        continue;
      }
      const artifactName = normalizeArtifactName(step.with?.name) ?? "__unnamed__";
      const producers = producersByArtifact.get(artifactName) ?? [];
      producers.push({ jobId: job.id, stepIndex });
      producersByArtifact.set(artifactName, producers);
    }
  }

  for (const job of facts.jobs) {
    for (const [stepIndex, step] of job.steps.entries()) {
      const normalizedUses = normalizeUses(step.uses);
      if (!normalizedUses || !DOWNLOAD_ARTIFACT_ACTIONS.has(normalizedUses)) {
        continue;
      }

      const requestedName = normalizeArtifactName(step.with?.name);
      const consumerDownloadsAll = !requestedName;
      const artifactNames = requestedName
        ? [requestedName]
        : Array.from(producersByArtifact.keys());

      for (const artifactName of artifactNames) {
        const producers = producersByArtifact.get(artifactName) ?? [];
        for (const producer of producers) {
          const key = [
            artifactName,
            producer.jobId,
            producer.stepIndex,
            job.id,
            stepIndex,
            consumerDownloadsAll ? "all" : "named",
          ].join("|");
          if (dedupe.has(key)) {
            continue;
          }
          dedupe.add(key);
          edges.push({
            artifactName,
            producerJobId: producer.jobId,
            producerStepIndex: producer.stepIndex,
            consumerJobId: job.id,
            consumerStepIndex: stepIndex,
            consumerDownloadsAll,
          });
        }
      }
    }
  }

  return edges;
}

export function collectUntrustedReachableJobIds(facts: WorkflowFacts): Set<string> {
  const hasUntrustedTrigger = facts.triggers.some((trigger) => isWorkflowTriggerUntrusted(trigger));
  if (!hasUntrustedTrigger) {
    return new Set<string>();
  }

  return new Set(
    facts.jobs.filter((job) => !isUntrustedRestrictedCondition(job.if)).map((job) => job.id),
  );
}

export function extractWorkflowCallBoundaryContext(
  parsed: unknown,
  facts: WorkflowFacts,
): WorkflowCallBoundaryContext {
  const root = asRecord(parsed);
  const onRecord = root ? asRecord(root.on) : null;
  const workflowCall = onRecord ? asRecord(onRecord.workflow_call) : null;

  const inputsRecord = workflowCall ? asRecord(workflowCall.inputs) : null;
  const declaredInputKeys = inputsRecord ? Object.keys(inputsRecord) : [];
  const requiredInputKeys = inputsRecord
    ? Object.entries(inputsRecord)
        .filter(([, value]) => asRecord(value)?.required === true)
        .map(([key]) => key)
    : [];

  const secretsRecord = workflowCall ? asRecord(workflowCall.secrets) : null;
  const declaredSecretKeys = secretsRecord ? Object.keys(secretsRecord) : [];
  const requiredSecretKeys = secretsRecord
    ? Object.entries(secretsRecord)
        .filter(([, value]) => asRecord(value)?.required === true)
        .map(([key]) => key)
    : [];

  const jobsWithInheritedSecrets = facts.jobs
    .filter(
      (job) => typeof job.secrets === "string" && job.secrets.trim().toLowerCase() === "inherit",
    )
    .map((job) => job.id);

  const jobsCallingReusableWorkflow = facts.jobs
    .filter((job) => typeof job.uses === "string" && job.uses.trim().length > 0)
    .map((job) => job.id);

  return {
    hasWorkflowCall: workflowCall !== null,
    declaredInputKeys,
    requiredInputKeys,
    declaredSecretKeys,
    requiredSecretKeys,
    jobsWithInheritedSecrets,
    jobsCallingReusableWorkflow,
  };
}
