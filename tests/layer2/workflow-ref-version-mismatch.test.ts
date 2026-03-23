import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { detectWorkflowRefVersionMismatch } from "../../src/layer2-static/detectors/workflow-ref-version-mismatch";

const originalFetch = globalThis.fetch;

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("workflow ref version mismatch detector", () => {
  it("flags hash-pinned actions whose version comment resolves to a different commit", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/git/ref/tags/v3.0.0")) {
          return new Response(
            JSON.stringify({
              object: {
                type: "commit",
                sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              },
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        return new Response("not found", { status: 404 });
      });

    const findings = await detectWorkflowRefVersionMismatch({
      filePath: ".github/workflows/release.yml",
      runtimeMode: "online",
      textContent: `name: release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v3.0.0
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              },
            ],
          },
        },
      },
    });

    expect(fetchSpy).toHaveBeenCalled();
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-ref-version-mismatch");
    expect(findings[0]?.evidence).toContain("v3.0.0");
  });

  it("does not flag matching version comments", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/git/ref/tags/v3.0.0")) {
        return new Response(
          JSON.stringify({
            object: {
              type: "commit",
              sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      return new Response("not found", { status: 404 });
    });

    const findings = await detectWorkflowRefVersionMismatch({
      filePath: ".github/workflows/release.yml",
      runtimeMode: "online",
      textContent: `name: release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v3.0.0
`,
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            steps: [
              {
                uses: "actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
