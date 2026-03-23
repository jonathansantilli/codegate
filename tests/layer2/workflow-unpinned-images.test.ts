import { describe, expect, it } from "vitest";
import { detectWorkflowUnpinnedImages } from "../../src/layer2-static/detectors/workflow-unpinned-images";

describe("workflow unpinned images detector", () => {
  it("flags workflow container and service images without immutable pins", () => {
    const findings = detectWorkflowUnpinnedImages({
      filePath: ".github/workflows/images.yml",
      textContent: [
        "jobs:",
        "  build:",
        "    container:",
        "      image: ghcr.io/acme/build",
        "    services:",
        "      redis:",
        "        image: redis:latest",
        "      pinned:",
        "        image: redis@sha256:7df1eeff67eb0ba84f6b9d2940765a6bb1158081426745c185a03b1507de6a09",
        "",
      ].join("\n"),
      parsed: {
        on: ["push"],
        jobs: {
          build: {
            container: {
              image: "ghcr.io/acme/build",
            },
            services: {
              redis: {
                image: "redis:latest",
              },
              pinned: {
                image:
                  "redis@sha256:7df1eeff67eb0ba84f6b9d2940765a6bb1158081426745c185a03b1507de6a09",
              },
            },
          },
        },
      },
    });

    expect(findings).toHaveLength(2);
    expect(findings.every((finding) => finding.rule_id === "workflow-unpinned-images")).toBe(true);
    expect(findings[0]?.evidence).toMatch(/ghcr\.io\/acme\/build|redis:latest/);
  });

  it("ignores non-workflow files", () => {
    const findings = detectWorkflowUnpinnedImages({
      filePath: "src/index.ts",
      textContent: "",
      parsed: {
        jobs: {
          build: {
            container: {
              image: "ghcr.io/acme/build",
            },
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
