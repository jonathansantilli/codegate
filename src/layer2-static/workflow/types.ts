export interface WorkflowStepFacts {
  uses?: string;
  run?: string;
  with?: Record<string, string>;
}

export interface WorkflowJobFacts {
  id: string;
  permissions?: unknown;
  steps: WorkflowStepFacts[];
}

export interface WorkflowFacts {
  triggers: string[];
  workflowPermissions?: unknown;
  jobs: WorkflowJobFacts[];
}
