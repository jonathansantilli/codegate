import type {
  DependabotCommitMessageFacts,
  DependabotCooldownFacts,
  DependabotFacts,
  DependabotGroupFacts,
  DependabotRuleFacts,
  DependabotScheduleFacts,
  DependabotUpdateFacts,
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

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const result = value.filter((entry): entry is string => typeof entry === "string");
  return result.length > 0 ? result : undefined;
}

function normalizeDependabotPath(value: string): string {
  return value.replaceAll("\\", "/");
}

export function isGitHubDependabotPath(path: string): boolean {
  return /(?:^|\/)\.github\/dependabot\.ya?ml$/iu.test(normalizeDependabotPath(path));
}

function extractSchedule(value: unknown): DependabotScheduleFacts | undefined {
  const schedule = asRecord(value);
  if (!schedule) {
    return undefined;
  }

  const result: DependabotScheduleFacts = {
    interval: asString(schedule.interval),
    day: asString(schedule.day),
    time: asString(schedule.time),
    timezone: asString(schedule.timezone),
  };

  return result.interval || result.day || result.time || result.timezone ? result : undefined;
}

function extractCooldown(value: unknown): DependabotCooldownFacts | undefined {
  const cooldown = asRecord(value);
  if (!cooldown) {
    return undefined;
  }

  const result: DependabotCooldownFacts = {
    defaultDays: asNumber(cooldown["default-days"]),
    semverMajorDays: asNumber(cooldown["semver-major-days"]),
    semverMinorDays: asNumber(cooldown["semver-minor-days"]),
    semverPatchDays: asNumber(cooldown["semver-patch-days"]),
  };

  return result.defaultDays !== undefined ||
    result.semverMajorDays !== undefined ||
    result.semverMinorDays !== undefined ||
    result.semverPatchDays !== undefined
    ? result
    : undefined;
}

function extractCommitMessage(value: unknown): DependabotCommitMessageFacts | undefined {
  const commitMessage = asRecord(value);
  if (!commitMessage) {
    return undefined;
  }

  const result: DependabotCommitMessageFacts = {
    prefix: asString(commitMessage.prefix),
    prefixDevelopment:
      asString(commitMessage["prefix-development"]) ?? asString(commitMessage.prefixDevelopment),
    include: asString(commitMessage.include),
  };

  return result.prefix || result.prefixDevelopment || result.include ? result : undefined;
}

function extractRuleFacts(value: unknown): DependabotRuleFacts | null {
  const rule = asRecord(value);
  if (!rule) {
    return null;
  }

  const result: DependabotRuleFacts = {
    dependencyName: asString(rule["dependency-name"]) ?? asString(rule.dependencyName),
    dependencyType: asString(rule["dependency-type"]) ?? asString(rule.dependencyType),
    versions: asStringArray(rule.versions),
    updateTypes: asStringArray(rule["update-types"]) ?? asStringArray(rule.updateTypes),
    patterns: asStringArray(rule.patterns),
  };

  if (
    result.dependencyName !== undefined ||
    result.dependencyType !== undefined ||
    result.versions !== undefined ||
    result.updateTypes !== undefined ||
    result.patterns !== undefined
  ) {
    return result;
  }

  return null;
}

function extractGroupFacts(value: unknown): DependabotGroupFacts | null {
  const group = asRecord(value);
  if (!group) {
    return null;
  }

  const result: DependabotGroupFacts = {
    dependencyType: asString(group["dependency-type"]) ?? asString(group.dependencyType),
    updateTypes: asStringArray(group["update-types"]) ?? asStringArray(group.updateTypes),
    patterns: asStringArray(group.patterns),
  };

  if (
    result.dependencyType !== undefined ||
    result.updateTypes !== undefined ||
    result.patterns !== undefined
  ) {
    return result;
  }

  return null;
}

function extractUpdateFacts(value: unknown): DependabotUpdateFacts | null {
  const update = asRecord(value);
  if (!update) {
    return null;
  }

  const allow = Array.isArray(update.allow)
    ? update.allow
        .map((entry) => extractRuleFacts(entry))
        .filter((entry): entry is DependabotRuleFacts => entry !== null)
    : undefined;
  const ignore = Array.isArray(update.ignore)
    ? update.ignore
        .map((entry) => extractRuleFacts(entry))
        .filter((entry): entry is DependabotRuleFacts => entry !== null)
    : undefined;

  const groupsRecord = asRecord(update.groups);
  const groups: Record<string, DependabotGroupFacts> = {};
  if (groupsRecord) {
    for (const [name, groupValue] of Object.entries(groupsRecord)) {
      const groupFacts = extractGroupFacts(groupValue);
      if (groupFacts) {
        groups[name] = groupFacts;
      }
    }
  }

  const result: DependabotUpdateFacts = {
    packageEcosystem: asString(update["package-ecosystem"]) ?? asString(update.packageEcosystem),
    directory: asString(update.directory),
    targetBranch: asString(update["target-branch"]) ?? asString(update.targetBranch),
    openPullRequestsLimit:
      asNumber(update["open-pull-requests-limit"]) ?? asNumber(update.openPullRequestsLimit),
    insecureExternalCodeExecution:
      asBoolean(update["insecure-external-code-execution"]) ??
      asBoolean(update.insecureExternalCodeExecution),
    schedule: extractSchedule(update.schedule),
    cooldown: extractCooldown(update.cooldown),
    labels: asStringArray(update.labels),
    assignees: asStringArray(update.assignees),
    reviewers: asStringArray(update.reviewers),
    registries: asStringArray(update.registries),
    commitMessage: extractCommitMessage(update["commit-message"] ?? update.commitMessage),
    allow,
    ignore,
    groups: Object.keys(groups).length > 0 ? groups : undefined,
  };

  if (
    result.packageEcosystem !== undefined ||
    result.directory !== undefined ||
    result.targetBranch !== undefined ||
    result.openPullRequestsLimit !== undefined ||
    result.insecureExternalCodeExecution !== undefined ||
    result.schedule !== undefined ||
    result.cooldown !== undefined ||
    result.labels !== undefined ||
    result.assignees !== undefined ||
    result.reviewers !== undefined ||
    result.registries !== undefined ||
    result.commitMessage !== undefined ||
    result.allow !== undefined ||
    result.ignore !== undefined ||
    result.groups !== undefined
  ) {
    return result;
  }

  return null;
}

export function extractDependabotFacts(parsed: unknown): DependabotFacts | null {
  const root = asRecord(parsed);
  if (!root) {
    return null;
  }

  const version = asNumber(root.version);
  const updatesRaw = Array.isArray(root.updates) ? root.updates : [];
  const updates = updatesRaw
    .map((entry) => extractUpdateFacts(entry))
    .filter((entry): entry is DependabotUpdateFacts => entry !== null);

  if (version === undefined && updates.length === 0) {
    return null;
  }

  return {
    version,
    updates,
  };
}
