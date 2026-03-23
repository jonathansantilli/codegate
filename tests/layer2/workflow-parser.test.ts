import { describe, expect, it } from "vitest";
import {
  extractWorkflowFacts,
  isGitHubWorkflowPath,
} from "../../src/layer2-static/workflow/parser";

describe("workflow parser", () => {
  it("detects github workflow file paths", () => {
    expect(isGitHubWorkflowPath(".github/workflows/ci.yml")).toBe(true);
    expect(isGitHubWorkflowPath(".github/workflows/release.yaml")).toBe(true);
    expect(isGitHubWorkflowPath("skills/security-review/SKILL.md")).toBe(false);
  });

  it("extracts trigger, jobs, step uses and run facts", () => {
    const facts = extractWorkflowFacts({
      on: ["pull_request", "workflow_dispatch"],
      permissions: "write-all",
      jobs: {
        test: {
          permissions: {
            contents: "write",
          },
          steps: [
            {
              uses: "actions/checkout@v4",
            },
            {
              run: "echo ${{ github.event.pull_request.title }}",
            },
          ],
        },
      },
    });

    expect(facts).not.toBeNull();
    expect(facts?.triggers).toEqual(expect.arrayContaining(["pull_request", "workflow_dispatch"]));
    expect(facts?.workflowPermissions).toBe("write-all");
    expect(facts?.jobs).toHaveLength(1);
    expect(facts?.jobs[0]?.steps[0]?.uses).toBe("actions/checkout@v4");
    expect(facts?.jobs[0]?.steps[1]?.run).toContain("${{");
  });

  it("returns null for non-workflow yaml", () => {
    expect(extractWorkflowFacts({ foo: "bar" })).toBeNull();
  });
});
