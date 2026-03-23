export interface WorkflowStepFacts {
  if?: string;
  uses?: string;
  run?: string;
  with?: Record<string, string>;
}

export interface WorkflowJobFacts {
  id: string;
  if?: string;
  uses?: string;
  with?: Record<string, string>;
  needs: string[];
  secrets?: unknown;
  permissions?: unknown;
  steps: WorkflowStepFacts[];
}

export interface WorkflowFacts {
  triggers: string[];
  workflowPermissions?: unknown;
  jobs: WorkflowJobFacts[];
}
