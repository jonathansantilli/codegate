import { afterEach, describe, expect, it, vi } from "vitest";
import { detectWorkflowStaleActionRefs } from "../../src/layer2-static/detectors/workflow-stale-action-refs";

function makeResponse(tags: Array<{ commit: { sha: string } }>, link = "") {
  return {
    ok: true,
    status: 200,
    json: async () => tags,
    headers: {
      get: (name: string) => {
        if (name.toLowerCase() === "link") {
          return link || null;
        }
        return null;
      },
    },
  };
}

describe("workflow stale action refs detector", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("flags commit pins that do not resolve to a tag", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        makeResponse([
          {
            commit: {
              sha: "1111111111111111111111111111111111111111",
            },
          },
        ]),
      ),
    );

    const findings = await detectWorkflowStaleActionRefs({
      filePath: ".github/workflows/ci.yml",
      textContent: [
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/checkout@009b9ae9e446ad8d9b8c809870b0fbcc5e03573e",
        "",
      ].join("\n"),
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@009b9ae9e446ad8d9b8c809870b0fbcc5e03573e",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-stale-action-refs");
    expect(findings[0]?.evidence).toContain("009b9ae9e446ad8d9b8c809870b0fbcc5e03573e");
  });

  it("ignores commit pins that point to a tag", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        makeResponse([
          {
            commit: {
              sha: "009b9ae9e446ad8d9b8c809870b0fbcc5e03573e",
            },
          },
        ]),
      ),
    );

    const findings = await detectWorkflowStaleActionRefs({
      filePath: ".github/workflows/ci.yml",
      textContent: [
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/checkout@009b9ae9e446ad8d9b8c809870b0fbcc5e03573e",
        "",
      ].join("\n"),
      parsed: {
        on: ["pull_request"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@009b9ae9e446ad8d9b8c809870b0fbcc5e03573e",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
