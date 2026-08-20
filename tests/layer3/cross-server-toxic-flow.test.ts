import { describe, expect, it } from "vitest";
import { layer3OutcomesToFindings, type DeepScanOutcome } from "../../src/pipeline";
import { detectToxicFlows } from "../../src/layer3-dynamic/toxic-flow";

function okOutcome(
  resourceId: string,
  tools: Array<{ name: string; description: string }>,
): DeepScanOutcome {
  return {
    resourceId,
    approved: true,
    status: "ok",
    result: {
      status: "ok",
      attempts: 1,
      elapsedMs: 1,
      metadata: { tools },
    },
  };
}

describe("detectToxicFlows enumeration", () => {
  it("reports every distinct chain, not just the first", () => {
    const findings = detectToxicFlows({
      scopeId: "server-a",
      tools: [
        { name: "read_jira", description: "read jira tickets with untrusted content" },
        { name: "read_email", description: "read email from untrusted sources" },
        { name: "read_ssh", description: "read local file ~/.ssh keys" },
        { name: "post_hook", description: "post to webhook endpoints" },
      ],
    });
    // 2 untrusted sources x 1 sensitive x 1 sink = 2 chains
    expect(findings).toHaveLength(2);
    expect(new Set(findings.map((finding) => finding.finding_id)).size).toBe(2);
  });

  it("caps reported chains", () => {
    const tools = [
      ...Array.from({ length: 5 }, (_, index) => ({
        name: `source-${index}`,
        description: "reads untrusted jira and read issue content",
      })),
      ...Array.from({ length: 5 }, (_, index) => ({
        name: `sensitive-${index}`,
        description: "reads local file credential material",
      })),
      ...Array.from({ length: 5 }, (_, index) => ({
        name: `sink-${index}`,
        description: "upload data to webhook",
      })),
    ];
    const findings = detectToxicFlows({ scopeId: "server-a", tools });
    expect(findings).toHaveLength(10);
  });
});

describe("cross-server toxic flow", () => {
  it("detects chains that span multiple servers", () => {
    const outcomes: DeepScanOutcome[] = [
      okOutcome("http:https://server-a.example", [
        { name: "read_issue", description: "read issue and ticket content from untrusted users" },
      ]),
      okOutcome("http:https://server-b.example", [
        { name: "read_secrets", description: "read local file ~/.ssh and credential stores" },
        { name: "send_report", description: "send summaries to an external endpoint via webhook" },
      ]),
    ];

    const findings = layer3OutcomesToFindings(outcomes);
    const workspace = findings.filter(
      (finding) => finding.category === "TOXIC_FLOW" && finding.file_path === "workspace",
    );
    expect(workspace.length).toBeGreaterThan(0);
    expect(workspace[0]?.description).toContain("server-a.example");
    expect(workspace[0]?.description).toContain("server-b.example");
  });

  it("does not duplicate single-server chains at workspace scope", () => {
    const outcomes: DeepScanOutcome[] = [
      okOutcome("http:https://server-a.example", [
        { name: "read_issue", description: "read issue content from untrusted users" },
        { name: "read_secrets", description: "read local file ~/.ssh keys" },
        { name: "send_report", description: "upload to webhook" },
      ]),
      okOutcome("http:https://server-b.example", [
        { name: "harmless", description: "format markdown tables" },
      ]),
    ];

    const findings = layer3OutcomesToFindings(outcomes);
    const perServer = findings.filter(
      (finding) =>
        finding.category === "TOXIC_FLOW" && finding.file_path === "http:https://server-a.example",
    );
    const workspace = findings.filter(
      (finding) => finding.category === "TOXIC_FLOW" && finding.file_path === "workspace",
    );
    expect(perServer.length).toBeGreaterThan(0);
    expect(workspace).toHaveLength(0);
  });
});
