import { describe, expect, it } from "vitest";
import { runStaticEngine, type StaticEngineConfig } from "../../src/layer2-static/engine";

const BASE_CONFIG: StaticEngineConfig = {
  knownSafeMcpServers: [],
  knownSafeFormatters: [],
  knownSafeLspServers: [],
  knownSafeHooks: [],
  blockedCommands: ["bash", "sh"],
  trustedApiDomains: [],
  unicodeAnalysis: true,
  checkIdeSettings: true,
  persona: "regular",
  runtimeMode: "offline",
  workflowAuditsEnabled: true,
};

describe("workflow template injection detector", () => {
  it("flags template expansion in run steps on untrusted triggers", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/pr.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request"],
            jobs: {
              test: {
                steps: [
                  {
                    run: "echo ${{ github.event.pull_request.title }}",
                  },
                ],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      true,
    );
  });

  it("flags known action sink inputs containing template expansions", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/pr.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request"],
            jobs: {
              test: {
                steps: [
                  {
                    uses: "actions/github-script@v7",
                    with: {
                      script: "core.info('${{ github.event.pull_request.title }}')",
                    },
                  },
                ],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      true,
    );
  });

  it("flags untrusted event expressions passed through generic action inputs", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/pr.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request"],
            jobs: {
              test: {
                steps: [
                  {
                    uses: "org/custom-action@v1",
                    with: {
                      command: "${{ github.event.pull_request.body }}",
                    },
                  },
                ],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      true,
    );
  });

  it("does not flag template expansion in trusted push-only workflows", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/push.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              test: {
                steps: [
                  {
                    run: "echo ${{ github.ref }}",
                  },
                ],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      false,
    );
  });

  it("flags privileged step conditions that trust issue or comment body content", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/comment-release.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["issue_comment"],
            jobs: {
              release: {
                steps: [
                  {
                    if: "contains(github.event.comment.body, '/release')",
                    run: "gh release create v1.2.3",
                  },
                ],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      true,
    );
  });

  it("does not flag benign template values that are not attacker-controlled event fields", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/pr.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["pull_request"],
            jobs: {
              test: {
                steps: [
                  {
                    run: "echo ${{ github.repository }}",
                  },
                ],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-template-injection")).toBe(
      false,
    );
  });
});
