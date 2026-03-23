import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { detectWorkflowImpostorCommit } from "../../src/layer2-static/detectors/workflow-impostor-commit";

const originalFetch = globalThis.fetch;

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("workflow impostor commit detector", () => {
  it("flags commit pins that do not exist in the referenced repository", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/commits/")) {
        return new Response("not found", { status: 404 });
      }

      return new Response("not found", { status: 404 });
    });

    const findings = await detectWorkflowImpostorCommit({
      filePath: ".github/workflows/ci.yml",
      runtimeMode: "online",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@c7d749a2d57b4b375d1ebcd17cfbfb60c676f18e
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@c7d749a2d57b4b375d1ebcd17cfbfb60c676f18e",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-impostor-commit");
    expect(findings[0]?.evidence).toContain("actions/checkout");
  });

  it("does not flag commits that exist in the referenced repository", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/commits/")) {
        return new Response(JSON.stringify({ sha: "c7d749a2d57b4b375d1ebcd17cfbfb60c676f18e" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      return new Response("not found", { status: 404 });
    });

    const findings = await detectWorkflowImpostorCommit({
      filePath: ".github/workflows/ci.yml",
      runtimeMode: "online",
      textContent: `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@c7d749a2d57b4b375d1ebcd17cfbfb60c676f18e
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@c7d749a2d57b4b375d1ebcd17cfbfb60c676f18e",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
