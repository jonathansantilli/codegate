import { afterEach, describe, expect, it, vi } from "vitest";
import { detectWorkflowArchivedUses } from "../../src/layer2-static/detectors/workflow-archived-uses";

function makeResponse(body: unknown, ok = true) {
  return {
    ok,
    status: ok ? 200 : 404,
    json: async () => body,
    headers: {
      get: () => null,
    },
  };
}

describe("workflow archived uses detector", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("flags archived repository uses in workflow files", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/repos/actions/setup-ruby")) {
          return makeResponse({ archived: true });
        }

        return makeResponse({ archived: false });
      }),
    );

    const findings = await detectWorkflowArchivedUses({
      filePath: ".github/workflows/archived.yml",
      textContent: [
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/setup-ruby@e932e7af67fc4a8fc77bd86b744acd4e42fe3543",
        "  reusable:",
        "    uses: actions/setup-ruby/.github/workflows/notreal.yml@e932e7af67fc4a8fc77bd86b744acd4e42fe3543",
        "",
      ].join("\n"),
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/setup-ruby@e932e7af67fc4a8fc77bd86b744acd4e42fe3543",
              },
            ],
          },
          reusable: {
            uses: "actions/setup-ruby/.github/workflows/notreal.yml@e932e7af67fc4a8fc77bd86b744acd4e42fe3543",
          },
        },
      },
    });

    expect(findings).toHaveLength(2);
    expect(findings.every((finding) => finding.rule_id === "workflow-archived-uses")).toBe(true);
    expect(findings[0]?.evidence).toContain("actions/setup-ruby");
    expect(findings[0]?.location.field).toMatch(/^jobs\./);
  });

  it("ignores non-workflow files", async () => {
    const findings = await detectWorkflowArchivedUses({
      filePath: "src/index.ts",
      textContent: "",
      parsed: {
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/setup-ruby@e932e7af67fc4a8fc77bd86b744acd4e42fe3543",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
