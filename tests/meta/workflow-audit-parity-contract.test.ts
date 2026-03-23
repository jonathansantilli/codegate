import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());
const checklistPath = resolve(root, "docs/workflow-audit-parity-checklist.md");

const expectedCheckedAuditIds = [
  "dangerous-triggers",
  "excessive-permissions",
  "known-vulnerable-actions",
  "template-injection",
  "unpinned-uses",
  "artipacked",
  "cache-poisoning",
  "github-env",
  "insecure-commands",
  "self-hosted-runner",
  "overprovisioned-secrets",
  "secrets-outside-env",
  "secrets-inherit",
  "use-trusted-publishing",
  "undocumented-permissions",
  "archived-uses",
  "stale-action-refs",
  "forbidden-uses",
  "ref-confusion",
  "ref-version-mismatch",
  "impostor-commit",
  "unpinned-images",
  "anonymous-definition",
  "concurrency-limits",
  "superfluous-actions",
  "misfeature",
  "obfuscation",
  "unsound-condition",
  "unsound-contains",
  "dependabot-cooldown",
  "dependabot-execution",
  "hardcoded-container-credentials",
  "unredacted-secrets",
  "bot-conditions",
  "workflow-call-boundary",
  "workflow-artifact-trust-chain",
  "workflow-pr-target-checkout-head",
] as const;

function readChecklist(): string {
  return readFileSync(checklistPath, "utf8");
}

describe("workflow audit parity checklist contract", () => {
  it("exists at the documented location", () => {
    expect(existsSync(checklistPath)).toBe(true);
  });

  it("marks every currently implemented workflow audit id as checked", () => {
    const checklist = readChecklist();

    for (const auditId of expectedCheckedAuditIds) {
      expect(checklist).toContain(`- [x] \`${auditId}\``);
    }
  });
});
