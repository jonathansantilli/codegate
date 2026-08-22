import { describe, expect, it } from "vitest";
import type { FleetConfig } from "../../src/fleet/fleet-config";
import type { ReportPayload } from "../../src/fleet/report-payload";
import { REPORT_PATH, sendReport } from "../../src/fleet/report-client";

const config: FleetConfig = { server: "https://guardian.acme.internal", token: "t-1" };

const payload: ReportPayload = {
  agent: { machineId: "m-1", version: "1.1.0" },
  host: { hostname: "dev-laptop-01" },
  collectedAt: "2026-08-22T12:00:00.000Z",
  inventory: { kb_version: "2026-08-20", tools: [], items: [] },
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("sendReport", () => {
  it("posts to the agent report endpoint with a bearer token", async () => {
    let seenUrl = "";
    let seenInit: RequestInit | undefined;

    await sendReport(payload, config, {
      fetch: (async (url: string, init: RequestInit) => {
        seenUrl = url;
        seenInit = init;
        return jsonResponse(200, { hostId: "h", reportId: "r", itemsAccepted: 0 });
      }) as unknown as typeof fetch,
    });

    expect(seenUrl).toBe(`https://guardian.acme.internal${REPORT_PATH}`);
    expect(seenInit?.method).toBe("POST");
    expect((seenInit?.headers as Record<string, string>).authorization).toBe("Bearer t-1");
    expect(JSON.parse(String(seenInit?.body)).agent.machineId).toBe("m-1");
  });

  it("returns what the server recorded", async () => {
    const result = await sendReport(payload, config, {
      fetch: (async () =>
        jsonResponse(200, {
          hostId: "h-1",
          reportId: "r-1",
          itemsAccepted: 14,
        })) as unknown as typeof fetch,
    });

    expect(result).toEqual({ ok: true, hostId: "h-1", reportId: "r-1", itemsAccepted: 14 });
  });

  // A laptop on a train is the normal case, not an error worth shouting about.
  it("treats an unreachable server as retryable", async () => {
    const result = await sendReport(payload, config, {
      fetch: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.retryable).toBe(true);
    expect(result.reason).toContain("could not reach");
  });

  it("treats a server error as retryable", async () => {
    const result = await sendReport(payload, config, {
      fetch: (async () => new Response("", { status: 503 })) as unknown as typeof fetch,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.retryable).toBe(true);
  });

  // Retrying a rejected token just burns battery and fills the server's log.
  it("treats a rejected token as not retryable and names the fix", async () => {
    for (const status of [401, 403]) {
      const result = await sendReport(payload, config, {
        fetch: (async () => new Response("", { status })) as unknown as typeof fetch,
      });

      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.retryable).toBe(false);
      expect(result.reason).toContain("CODEGATE_TOKEN");
    }
  });

  it("treats an oversized report as not retryable", async () => {
    const result = await sendReport(payload, config, {
      fetch: (async () => new Response("", { status: 413 })) as unknown as typeof fetch,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.retryable).toBe(false);
    expect(result.reason).toContain("too large");
  });

  it("surfaces the server's own reason for a rejected report", async () => {
    const result = await sendReport(payload, config, {
      fetch: (async () =>
        jsonResponse(400, { error: "Invalid report" })) as unknown as typeof fetch,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.retryable).toBe(false);
    expect(result.reason).toContain("Invalid report");
  });

  it("does not crash when a rejection carries no JSON body", async () => {
    const result = await sendReport(payload, config, {
      fetch: (async () => new Response("<html>", { status: 400 })) as unknown as typeof fetch,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("400");
  });

  it("treats a non-JSON success body as retryable rather than claiming success", async () => {
    const result = await sendReport(payload, config, {
      fetch: (async () => new Response("not json", { status: 200 })) as unknown as typeof fetch,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.retryable).toBe(true);
  });

  it("gives up rather than hanging when the server never answers", async () => {
    const result = await sendReport(payload, config, {
      timeoutMs: 5,
      fetch: ((_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        })) as unknown as typeof fetch,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.retryable).toBe(true);
  });
});
