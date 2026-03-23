import { describe, expect, it } from "vitest";
import { detectDependabotAutoMerge } from "../../src/layer2-static/detectors/dependabot-auto-merge";

describe("dependabot auto merge detector", () => {
  it("flags pull_request_target auto-merge flow gated only by dependabot actor", () => {
    const findings = detectDependabotAutoMerge({
      filePath: ".github/workflows/automerge.yml",
      textContent: `on: [pull_request_target]
jobs:
  automerge:
    if: github.actor == 'dependabot[bot]'
    steps:
      - run: gh pr merge --auto --merge "$PR_URL"
`,
      parsed: {
        on: ["pull_request_target"],
        jobs: {
          automerge: {
            if: "github.actor == 'dependabot[bot]'",
            steps: [
              {
                run: 'gh pr merge --auto --merge "$PR_URL"',
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("dependabot-auto-merge");
    expect(findings[0]?.severity).toBe("HIGH");
  });

  it("does not flag when strict repository boundary checks are present", () => {
    const findings = detectDependabotAutoMerge({
      filePath: ".github/workflows/automerge.yml",
      textContent: `on: [pull_request_target]
jobs:
  automerge:
    if: github.actor == 'dependabot[bot]' && github.repository == github.event.pull_request.head.repo.full_name
    steps:
      - run: gh pr merge --auto --merge "$PR_URL"
`,
      parsed: {
        on: ["pull_request_target"],
        jobs: {
          automerge: {
            if: "github.actor == 'dependabot[bot]' && github.repository == github.event.pull_request.head.repo.full_name",
            steps: [
              {
                run: 'gh pr merge --auto --merge "$PR_URL"',
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
