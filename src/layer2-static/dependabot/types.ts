export interface DependabotScheduleFacts {
  interval?: string;
  day?: string;
  time?: string;
  timezone?: string;
}

export interface DependabotCooldownFacts {
  defaultDays?: number;
  semverMajorDays?: number;
  semverMinorDays?: number;
  semverPatchDays?: number;
}

export interface DependabotCommitMessageFacts {
  prefix?: string;
  prefixDevelopment?: string;
  include?: string;
}

export interface DependabotRuleFacts {
  dependencyName?: string;
  dependencyType?: string;
  versions?: string[];
  updateTypes?: string[];
  patterns?: string[];
}

export interface DependabotGroupFacts {
  dependencyType?: string;
  updateTypes?: string[];
  patterns?: string[];
}

export interface DependabotUpdateFacts {
  packageEcosystem?: string;
  directory?: string;
  targetBranch?: string;
  openPullRequestsLimit?: number;
  insecureExternalCodeExecution?: boolean;
  schedule?: DependabotScheduleFacts;
  cooldown?: DependabotCooldownFacts;
  labels?: string[];
  assignees?: string[];
  reviewers?: string[];
  registries?: string[];
  commitMessage?: DependabotCommitMessageFacts;
  allow?: DependabotRuleFacts[];
  ignore?: DependabotRuleFacts[];
  groups?: Record<string, DependabotGroupFacts>;
}

export interface DependabotFacts {
  version?: number;
  updates: DependabotUpdateFacts[];
}
