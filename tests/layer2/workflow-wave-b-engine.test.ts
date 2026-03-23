import { afterEach, describe, expect, it, vi } from "vitest";
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
  persona: "auditor",
  runtimeMode: "online",
  workflowAuditsEnabled: true,
};

function buildWorkflowFixture() {
  const textContent = [
    "name: ci",
    "on: [push]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    container:",
    "      image: node:latest",
    "    steps:",
    "      - uses: actions/setup-ruby@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "      - uses: actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "      - uses: actions/cache@cccccccccccccccccccccccccccccccccccccccc # v3.0.0",
    "",
  ].join("\n");

  const parsed = {
    on: ["push"],
    jobs: {
      build: {
        "runs-on": "ubuntu-latest",
        container: {
          image: "node:latest",
        },
        steps: [
          { uses: "actions/setup-ruby@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
          { uses: "actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
          { uses: "actions/cache@cccccccccccccccccccccccccccccccccccccccc" },
        ],
      },
    },
  };

  return { textContent, parsed };
}

describe("workflow wave B engine integration", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("surfaces Wave B findings through runStaticEngine in online mode", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL) => {
        const url = String(input);

        if (url.includes("/repos/actions/setup-ruby")) {
          return new Response(JSON.stringify({ archived: true }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        if (url.includes("/repos/actions/checkout/tags")) {
          return new Response(JSON.stringify([]), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        if (url.includes("/repos/actions/cache/git/ref/tags/v3.0.0")) {
          return new Response(
            JSON.stringify({
              object: {
                type: "commit",
                sha: "dddddddddddddddddddddddddddddddddddddddd",
              },
            }),
            {
              status: 200,
              headers: { "content-type": "application/json" },
            },
          );
        }

        if (url.includes("/repos/actions/checkout/commits/")) {
          return new Response("not found", { status: 404 });
        }

        return new Response("not found", { status: 404 });
      }),
    );

    const fixture = buildWorkflowFixture();

    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/ci.yml",
          format: "yaml",
          parsed: fixture.parsed,
          textContent: fixture.textContent,
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: BASE_CONFIG,
    });

    const ruleIds = new Set(findings.map((finding) => finding.rule_id));

    expect(ruleIds.has("workflow-archived-uses")).toBe(true);
    expect(ruleIds.has("workflow-stale-action-refs")).toBe(true);
    expect(ruleIds.has("workflow-ref-version-mismatch")).toBe(true);
    expect(ruleIds.has("workflow-impostor-commit")).toBe(true);
    expect(ruleIds.has("workflow-unpinned-images")).toBe(true);
  });
});
