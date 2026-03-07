import { parse as parseJsonc } from "jsonc-parser";
import type { DiscoveryFormat } from "../types/discovery.js";
import type { Finding } from "../types/finding.js";
import { generateUnifiedDiff } from "./diff-generator.js";
import { buildQuarantinePlaceholder } from "./actions/quarantine.js";
import { removeField } from "./actions/remove-field.js";
import { replaceValue } from "./actions/replace-value.js";
import { stripInvisibleUnicode } from "./actions/strip-unicode.js";

export interface RemediationFile {
  path: string;
  format: DiscoveryFormat;
  content: string;
}

export type RemediationAction =
  | {
      type: "remove_field";
      fieldPath: string;
    }
  | {
      type: "replace_value";
      fieldPath: string;
      value: unknown;
    }
  | {
      type: "strip_unicode";
    }
  | {
      type: "quarantine";
    };

export interface RemediationPlanItem {
  findingId: string;
  filePath: string;
  action: RemediationAction;
  originalContent: string;
  updatedContent: string;
  diff: string;
}

export interface RemediationPlanInput {
  findings: Finding[];
  files: RemediationFile[];
}

function parseStructuredContent(format: DiscoveryFormat, content: string): unknown {
  if (format === "json") {
    return JSON.parse(content) as unknown;
  }
  if (format === "jsonc") {
    return parseJsonc(content) as unknown;
  }
  return null;
}

function serializeStructuredContent(format: DiscoveryFormat, value: unknown): string {
  if (format === "json" || format === "jsonc") {
    return `${JSON.stringify(value, null, 2)}\n`;
  }
  return String(value ?? "");
}

function chooseAction(finding: Finding, fieldPath: string | undefined): RemediationAction | null {

  if (finding.category === "ENV_OVERRIDE" && fieldPath) {
    return { type: "remove_field", fieldPath };
  }

  if (finding.category === "CONSENT_BYPASS" && fieldPath) {
    if (fieldPath === "enableAllProjectMcpServers") {
      return {
        type: "replace_value",
        fieldPath,
        value: false,
      };
    }
    return { type: "remove_field", fieldPath };
  }

  if (finding.category === "RULE_INJECTION") {
    return { type: "strip_unicode" };
  }

  if (
    finding.category === "COMMAND_EXEC" ||
    finding.category === "SYMLINK_ESCAPE" ||
    finding.category === "GIT_HOOK"
  ) {
    return { type: "quarantine" };
  }

  return null;
}

export function applyRemediationAction(
  action: RemediationAction,
  file: RemediationFile,
  finding: Finding,
): { updatedContent: string; changed: boolean } {
  if (action.type === "strip_unicode") {
    const stripped = stripInvisibleUnicode(file.content);
    return {
      updatedContent: stripped.content,
      changed: stripped.changed,
    };
  }

  if (action.type === "quarantine") {
    return {
      updatedContent: buildQuarantinePlaceholder(
        file.path,
        finding.description,
        ".codegate-backup/quarantine",
      ),
      changed: true,
    };
  }

  const parsed = parseStructuredContent(file.format, file.content);
  if (parsed === null) {
    return { updatedContent: file.content, changed: false };
  }

  if (action.type === "remove_field") {
    const result = removeField(parsed, action.fieldPath);
    return {
      updatedContent: result.changed ? serializeStructuredContent(file.format, result.value) : file.content,
      changed: result.changed,
    };
  }

  const result = replaceValue(parsed, action.fieldPath, action.value);
  return {
    updatedContent: result.changed ? serializeStructuredContent(file.format, result.value) : file.content,
    changed: result.changed,
  };
}

export function planRemediation(input: RemediationPlanInput): RemediationPlanItem[] {
  const filesByPath = new Map(input.files.map((file) => [file.path, file] as const));
  const plan: RemediationPlanItem[] = [];

  for (const finding of input.findings) {
    if (!finding.fixable || finding.suppressed) {
      continue;
    }
    const targetPath = finding.source_config?.file_path ?? finding.file_path;
    const fieldPath = finding.source_config?.field ?? finding.location.field;
    const file = filesByPath.get(targetPath);
    if (!file) {
      continue;
    }

    const action = chooseAction(finding, fieldPath);
    if (!action) {
      continue;
    }

    const result = applyRemediationAction(action, file, finding);
    if (!result.changed) {
      continue;
    }

    const diff = generateUnifiedDiff({
      filePath: file.path,
      before: file.content,
      after: result.updatedContent,
    });

    plan.push({
      findingId: finding.finding_id,
      filePath: file.path,
      action,
      originalContent: file.content,
      updatedContent: result.updatedContent,
      diff,
    });
  }

  return plan;
}
