import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { InventorySummary } from "../../src/commands/inventory-command";
import { runReport, type ReportCommandDeps } from "../../src/commands/report-command";
import type { Finding } from "../../src/types/finding";
import { SERVER_ENV, TOKEN_ENV } from "../../src/fleet/fleet-config";

const CONTENT = "skill body";

function summary(exists = true): InventorySummary {
  return {
    kb_version: "2026-08-20",
    tools: [{ name: "claude-code", version_range: ">=1" }],
    items: [
      {
        tool: "claude-code",
        kind: "skill",
        scope: "user",
        pattern: ".claude/skills/*/SKILL.md",
        path: "/home/u/.claude/skills/podcast/SKILL.md",
        exists,
        risk_surface: [],
        resolved_against: "/home/u",
      },
    ],
  };
}

function deps(overrides: Partial<ReportCommandDeps> = {}): ReportCommandDeps {
  return {
    homeDir: () => mkdtempSync(join(tmpdir(), "codegate-report-")),
    env: {
      [SERVER_ENV]: "https://guardian.acme.internal",
      [TOKEN_ENV]: "t-1",
    } as NodeJS.ProcessEnv,
    collectInventory: () => summary(),
    agentVersion: "1.1.0",
    now: () => new Date("2026-08-22T12:00:00.000Z"),
    hostFacts: () => ({ hostname: "dev-laptop-01", platform: "darwin", username: "u" }),
    readFile: () => CONTENT,
    fileSize: () => CONTENT.length,
    fetch: (async () =>
      new Response(JSON.stringify({ hostId: "h-1", reportId: "r-1", itemsAccepted: 1 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch,
    ...overrides,
  };
}

describe("runReport", () => {
  it("sends the inventory and reports what the server accepted", async () => {
    const outcome = await runReport(deps());

    expect(outcome).toEqual({
      status: "sent",
      hostId: "h-1",
      itemsAccepted: 1,
      itemsHashed: 1,
      findingsSent: null,
    });
  });

  it("sends identity, host facts and hashed artifacts", async () => {
    let body: Record<string, never> | undefined;
    await runReport(
      deps({
        fetch: (async (_url: string, init: RequestInit) => {
          body = JSON.parse(String(init.body));
          return new Response(JSON.stringify({ hostId: "h", reportId: "r", itemsAccepted: 1 }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }) as unknown as typeof fetch,
      }),
    );

    const sent = body as unknown as {
      agent: { machineId: string; version: string };
      host: { hostname: string };
      collectedAt: string;
      inventory: { items: { sha256?: string }[] };
    };
    expect(sent.agent.version).toBe("1.1.0");
    expect(sent.agent.machineId.length).toBeGreaterThan(0);
    expect(sent.host.hostname).toBe("dev-laptop-01");
    expect(sent.collectedAt).toBe("2026-08-22T12:00:00.000Z");
    expect(sent.inventory.items[0].sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  // Being unconfigured is the expected state on a fresh machine, not a failure.
  it("reports plainly when no server is configured", async () => {
    const outcome = await runReport(deps({ env: {} as NodeJS.ProcessEnv }));

    expect(outcome.status).toBe("not-configured");
    if (outcome.status !== "not-configured") return;
    expect(outcome.reason).toContain(SERVER_ENV);
  });

  it("does not contact a server when it is not configured", async () => {
    let called = false;
    await runReport(
      deps({
        env: {} as NodeJS.ProcessEnv,
        fetch: (async () => {
          called = true;
          return new Response("{}", { status: 200 });
        }) as unknown as typeof fetch,
      }),
    );

    expect(called).toBe(false);
  });

  it("passes through a retryable transport failure", async () => {
    const outcome = await runReport(
      deps({
        fetch: (async () => {
          throw new Error("ECONNREFUSED");
        }) as unknown as typeof fetch,
      }),
    );

    expect(outcome.status).toBe("failed");
    if (outcome.status !== "failed") return;
    expect(outcome.retryable).toBe(true);
  });

  it("marks a rejected token as not worth retrying", async () => {
    const outcome = await runReport(
      deps({ fetch: (async () => new Response("", { status: 401 })) as unknown as typeof fetch }),
    );

    expect(outcome.status).toBe("failed");
    if (outcome.status !== "failed") return;
    expect(outcome.retryable).toBe(false);
  });

  it("counts artifacts it could not hash separately from those it sent", async () => {
    const outcome = await runReport(deps({ collectInventory: () => summary(false) }));

    expect(outcome.status).toBe("sent");
    if (outcome.status !== "sent") return;
    expect(outcome.itemsHashed).toBe(0);
  });

  it("keeps the same machine id across two reports from one machine", async () => {
    const home = mkdtempSync(join(tmpdir(), "codegate-report-stable-"));
    const ids: string[] = [];
    const capture = deps({
      homeDir: () => home,
      fetch: (async (_url: string, init: RequestInit) => {
        ids.push(JSON.parse(String(init.body)).agent.machineId);
        return new Response(JSON.stringify({ hostId: "h", reportId: "r", itemsAccepted: 1 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }) as unknown as typeof fetch,
    });

    await runReport(capture);
    await runReport(capture);

    expect(ids).toHaveLength(2);
    expect(ids[0]).toBe(ids[1]);
  });
});

describe("runReport with findings", () => {
  // Shaped as the scanner emits it; only the fields the wire format keeps.
  const finding = {
    finding_id: "f-1",
    rule_id: "known-malicious-content",
    fingerprint: "sha256:fp-1",
    severity: "CRITICAL",
    category: "RULE_INJECTION",
    layer: "L2",
    file_path: "/home/u/.claude/skills/podcast/SKILL.md",
    location: { line: 7, column: 27 },
    description: "Skill matches a known-bad indicator",
    affected_tools: [],
    owasp: ["ASI02"],
    cwe: "CWE-506",
    confidence: "HIGH",
    fixable: false,
    remediation_actions: [],
    suppressed: false,
  } as unknown as Finding;

  it("sends findings when a scan ran, and ties each to the file's hash", async () => {
    let body: { findings?: { sha256?: string; line?: number }[] } | undefined;

    const outcome = await runReport(
      deps({
        collectFindings: () => [finding],
        fetch: (async (_url: string, init: RequestInit) => {
          body = JSON.parse(String(init.body));
          return new Response(JSON.stringify({ hostId: "h", reportId: "r", itemsAccepted: 1 }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }) as unknown as typeof fetch,
      }),
    );

    expect(outcome.status).toBe("sent");
    if (outcome.status !== "sent") return;
    expect(outcome.findingsSent).toBe(1);
    expect(body?.findings?.[0].sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(body?.findings?.[0].line).toBe(7);
  });

  // Omitted and empty mean different things: the server treats an empty list
  // as "this machine is clean" and an absent one as "nothing asserted".
  it("omits findings entirely when no scan ran", async () => {
    let body: { findings?: unknown } | undefined;

    await runReport(
      deps({
        fetch: (async (_url: string, init: RequestInit) => {
          body = JSON.parse(String(init.body));
          return new Response(JSON.stringify({ hostId: "h", reportId: "r", itemsAccepted: 1 }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }) as unknown as typeof fetch,
      }),
    );

    expect(body).not.toHaveProperty("findings");
  });

  it("sends an empty list when a scan ran and found nothing", async () => {
    let body: { findings?: unknown[] } | undefined;

    const outcome = await runReport(
      deps({
        collectFindings: () => [],
        fetch: (async (_url: string, init: RequestInit) => {
          body = JSON.parse(String(init.body));
          return new Response(JSON.stringify({ hostId: "h", reportId: "r", itemsAccepted: 1 }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }) as unknown as typeof fetch,
      }),
    );

    expect(body?.findings).toEqual([]);
    expect(outcome.status).toBe("sent");
    if (outcome.status !== "sent") return;
    expect(outcome.findingsSent).toBe(0);
  });
});
