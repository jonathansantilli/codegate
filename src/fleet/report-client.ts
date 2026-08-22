import type { FleetConfig } from "./fleet-config.js";
import type { ReportPayload } from "./report-payload.js";

/**
 * Sends one check-in to a Guardian server.
 *
 * Single-shot by design: the caller decides whether a failure is worth
 * retrying, because a scheduled agent should give up quickly and try again on
 * its next run rather than hold a laptop's CPU retrying a server that is down.
 */

export const REPORT_PATH = "/api/agent/report";
const DEFAULT_TIMEOUT_MS = 30_000;

export interface SendReportDeps {
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
}

export type SendReportResult =
  | { ok: true; hostId: string; reportId: string; itemsAccepted: number }
  | { ok: false; reason: string; retryable: boolean };

interface AcceptedBody {
  hostId?: unknown;
  reportId?: unknown;
  itemsAccepted?: unknown;
}

function asText(value: unknown): string {
  return typeof value === "string" ? value : "";
}

export async function sendReport(
  payload: ReportPayload,
  config: FleetConfig,
  deps: SendReportDeps = {},
): Promise<SendReportResult> {
  const doFetch = deps.fetch ?? globalThis.fetch;
  const url = `${config.server}${REPORT_PATH}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), deps.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  let response: Response;
  try {
    response = await doFetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${config.token}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // The server being unreachable is the normal case for a laptop on a train.
    return { ok: false, reason: `could not reach ${url}: ${message}`, retryable: true };
  } finally {
    clearTimeout(timeout);
  }

  if (response.status === 401 || response.status === 403) {
    return {
      ok: false,
      reason: `${url} rejected this machine's token (${response.status}). Check CODEGATE_TOKEN, or re-enrol the machine.`,
      retryable: false,
    };
  }

  if (response.status === 413) {
    return {
      ok: false,
      reason: `report too large for ${url} (413). This machine reported more artifacts than the server accepts.`,
      retryable: false,
    };
  }

  if (response.status >= 500) {
    return { ok: false, reason: `${url} returned ${response.status}`, retryable: true };
  }

  if (!response.ok) {
    let detail = "";
    try {
      detail = asText((await response.json())?.error);
    } catch {
      // body was not the JSON we expected; the status alone has to do
    }
    return {
      ok: false,
      reason: `${url} rejected the report (${response.status})${detail ? `: ${detail}` : ""}`,
      retryable: false,
    };
  }

  let body: AcceptedBody;
  try {
    body = (await response.json()) as AcceptedBody;
  } catch {
    return { ok: false, reason: `${url} returned a body that is not JSON`, retryable: true };
  }

  return {
    ok: true,
    hostId: asText(body.hostId),
    reportId: asText(body.reportId),
    itemsAccepted: typeof body.itemsAccepted === "number" ? body.itemsAccepted : 0,
  };
}
