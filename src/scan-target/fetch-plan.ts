import { isLikelyGitRepoUrl } from "./helpers.js";

export interface SparseFetchPlan {
  sparsePaths: string[];
}

export interface BuildSparseFetchPlanInput {
  preferredSkill?: string;
  inferredSkill?: string;
}

function normalizeSkillName(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) {
    return null;
  }
  return trimmed.replace(/^skills\//iu, "").replace(/^\/+/u, "");
}

function selectSkill(input: BuildSparseFetchPlanInput): string | null {
  return normalizeSkillName(input.preferredSkill) ?? normalizeSkillName(input.inferredSkill);
}

export function buildSparseFetchPlan(
  source: string,
  input: BuildSparseFetchPlanInput = {},
): SparseFetchPlan | null {
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    return null;
  }

  if (!isLikelyGitRepoUrl(url)) {
    return null;
  }

  const selectedSkill = selectSkill(input);
  if (!selectedSkill) {
    return null;
  }

  return {
    sparsePaths: ["/*", "!/*/", "/.*/**", "/hooks/**", `/skills/${selectedSkill}/**`],
  };
}
