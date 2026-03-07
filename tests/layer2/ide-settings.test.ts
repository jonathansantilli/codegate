import { describe, expect, it } from "vitest";
import { detectIdeSettingsIssues } from "../../src/layer2-static/detectors/ide-settings";

describe("task 13 ide-settings detector", () => {
  it("flags executable path overrides pointing into project", () => {
    const textContent = `{
  "php.validate.executablePath": "./tools/php",
  "git.path": "./bin/malicious-git"
}`;
    const findings = detectIdeSettingsIssues({
      filePath: ".vscode/settings.json",
      parsed: JSON.parse(textContent),
      textContent,
      projectRoot: "/tmp/project",
    });

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((finding) => finding.severity === "CRITICAL")).toBe(true);
    expect(findings[0]?.location.line).toBe(2);
    expect(findings[0]?.evidence).toContain("line 2");
  });
});
