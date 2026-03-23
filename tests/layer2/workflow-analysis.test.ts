import { describe, expect, it } from "vitest";
import { extractWorkflowFacts } from "../../src/layer2-static/workflow/parser";
import {
  buildWorkflowNeedsGraph,
  collectArtifactTransferEdges,
  collectTransitiveDependencies,
  collectTransitiveDependents,
  collectUntrustedReachableJobIds,
  extractWorkflowCallBoundaryContext,
} from "../../src/layer2-static/workflow/analysis";

describe("workflow analysis helpers", () => {
  it("builds dependency graph and computes transitive closures", () => {
    const facts = extractWorkflowFacts({
      on: ["push"],
      jobs: {
        build: {},
        test: { needs: "build" },
        package: { needs: ["test"] },
        deploy: { needs: ["package"] },
      },
    });

    expect(facts).not.toBeNull();
    const graph = buildWorkflowNeedsGraph(facts!);
    expect(graph.get("deploy")).toEqual(["package"]);
    expect(graph.get("test")).toEqual(["build"]);

    expect(Array.from(collectTransitiveDependencies(facts!, ["deploy"])).sort()).toEqual([
      "build",
      "package",
      "test",
    ]);

    expect(Array.from(collectTransitiveDependents(facts!, ["build"])).sort()).toEqual([
      "deploy",
      "package",
      "test",
    ]);
  });

  it("links artifact producer and consumer jobs", () => {
    const facts = extractWorkflowFacts({
      on: ["pull_request"],
      jobs: {
        build: {
          steps: [
            {
              uses: "actions/upload-artifact@v4",
              with: { name: "dist" },
            },
          ],
        },
        verify: {
          needs: "build",
          steps: [
            {
              uses: "actions/download-artifact@v4",
              with: { name: "dist" },
            },
          ],
        },
        aggregate: {
          steps: [
            {
              uses: "actions/download-artifact@v4",
            },
          ],
        },
      },
    });

    expect(facts).not.toBeNull();
    const edges = collectArtifactTransferEdges(facts!);
    expect(edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          artifactName: "dist",
          producerJobId: "build",
          consumerJobId: "verify",
        }),
        expect.objectContaining({
          artifactName: "dist",
          producerJobId: "build",
          consumerJobId: "aggregate",
          consumerDownloadsAll: true,
        }),
      ]),
    );
  });

  it("identifies untrusted-trigger jobs while honoring restrictive bot-only conditions", () => {
    const facts = extractWorkflowFacts({
      on: ["pull_request_target"],
      jobs: {
        open: {},
        bot_only: {
          if: "github.actor == 'dependabot[bot]'",
        },
        guarded: {
          if: "github.event.pull_request.head.repo.fork == false",
        },
      },
    });

    expect(facts).not.toBeNull();
    expect(Array.from(collectUntrustedReachableJobIds(facts!)).sort()).toEqual(["open"]);
  });

  it("extracts workflow_call boundary context including inherited secrets and reusable workflow jobs", () => {
    const parsed = {
      on: {
        workflow_call: {
          inputs: {
            config_path: {
              required: true,
              type: "string",
            },
          },
          secrets: {
            publish_token: {
              required: true,
            },
          },
        },
      },
      jobs: {
        prepare: {
          secrets: "inherit",
          steps: [{ run: "echo prep" }],
        },
        invoke_release: {
          uses: "org/shared/.github/workflows/release.yml@v1",
          with: {
            publish: "true",
          },
        },
      },
    };

    const facts = extractWorkflowFacts(parsed);
    expect(facts).not.toBeNull();

    const boundary = extractWorkflowCallBoundaryContext(parsed, facts!);
    expect(boundary.hasWorkflowCall).toBe(true);
    expect(boundary.declaredInputKeys).toEqual(["config_path"]);
    expect(boundary.requiredInputKeys).toEqual(["config_path"]);
    expect(boundary.declaredSecretKeys).toEqual(["publish_token"]);
    expect(boundary.requiredSecretKeys).toEqual(["publish_token"]);
    expect(boundary.jobsWithInheritedSecrets).toEqual(["prepare"]);
    expect(boundary.jobsCallingReusableWorkflow).toEqual(["invoke_release"]);
  });
});
