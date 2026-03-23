import type { RuntimeMode } from "../../config.js";
import { loadBundledGithubAdvisories, type GithubMetadataClientOptions } from "../github/client.js";
import type { AdvisoryPayload } from "../github/cache.js";

export interface LoadKnownVulnerableActionsOptions extends GithubMetadataClientOptions {
  runtimeMode?: RuntimeMode;
}

export function loadKnownVulnerableActions(
  options: LoadKnownVulnerableActionsOptions = {},
): AdvisoryPayload {
  return loadBundledGithubAdvisories(options);
}
