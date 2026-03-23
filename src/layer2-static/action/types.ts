export interface ActionStepFacts {
  id?: string;
  name?: string;
  uses?: string;
  run?: string;
  if?: string;
  shell?: string;
  workingDirectory?: string;
  with?: Record<string, string>;
  env?: Record<string, string>;
}

export interface ActionRunsFacts {
  using?: string;
  main?: string;
  pre?: string;
  post?: string;
  image?: string;
  args?: string[];
  steps?: ActionStepFacts[];
}

export interface ActionInputFacts {
  description?: string;
  required?: boolean;
  default?: string;
  deprecationMessage?: string;
}

export interface ActionOutputFacts {
  description?: string;
  value?: string;
}

export interface ActionFacts {
  name?: string;
  description?: string;
  author?: string;
  branding?: Record<string, unknown>;
  inputs?: Record<string, ActionInputFacts>;
  outputs?: Record<string, ActionOutputFacts>;
  runs?: ActionRunsFacts;
}
