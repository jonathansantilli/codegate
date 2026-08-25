import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fleetConfigPath, type FleetConfigDeps } from "./fleet-config.js";
import { resolveMachineId, type MachineIdentityDeps } from "./machine-identity.js";

/**
 * Exchanges an enrolment code for the token this machine reports with, and
 * writes it where `codegate report` will find it.
 *
 * The code is the only credential a machine has before it is enrolled, so it
 * is spent once and the resulting token is stored owner-readable only.
 */

export const ENROL_PATH = "/api/agent/enrol";
const DEFAULT_TIMEOUT_MS = 30_000;
/** The token is a fleet credential; nobody else on the machine needs it. */
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

export interface EnrolDeps extends MachineIdentityDeps, FleetConfigDeps {
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  writeConfig?: (path: string, contents: string) => void;
}

export type EnrolResult =
  { ok: true; server: string; configPath: string } | { ok: false; reason: string };

function normalizeServer(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:"
      ? url.origin + url.pathname.replace(/\/+$/, "")
      : null;
  } catch {
    return null;
  }
}

export async function enrolMachine(
  input: { server: string; code: string },
  deps: EnrolDeps = {},
): Promise<EnrolResult> {
  const server = normalizeServer(input.server);
  if (!server) {
    return { ok: false, reason: `server must be an absolute http(s) URL; got "${input.server}".` };
  }

  const url = `${server}${ENROL_PATH}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), deps.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  let response: Response;
  try {
    response = await (deps.fetch ?? globalThis.fetch)(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: input.code, machineId: resolveMachineId(deps) }),
      signal: controller.signal,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, reason: `could not reach ${url}: ${message}` };
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    let detail = "";
    try {
      const body = (await response.json()) as { error?: unknown };
      detail = typeof body.error === "string" ? body.error : "";
    } catch {
      // the status alone will have to do
    }
    return {
      ok: false,
      reason: detail || `${url} refused the enrolment (${response.status})`,
    };
  }

  let body: { token?: unknown };
  try {
    body = (await response.json()) as { token?: unknown };
  } catch {
    return { ok: false, reason: `${url} returned a body that is not JSON` };
  }

  if (typeof body.token !== "string" || body.token.length === 0) {
    return { ok: false, reason: `${url} did not return a token` };
  }

  const configPath = fleetConfigPath(deps);
  const contents = `${JSON.stringify({ server, token: body.token }, null, 2)}\n`;

  try {
    if (deps.writeConfig) {
      deps.writeConfig(configPath, contents);
    } else {
      mkdirSync(dirname(configPath), { recursive: true, mode: DIR_MODE });
      writeFileSync(configPath, contents, { encoding: "utf8", mode: FILE_MODE });
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, reason: `enrolled, but could not write ${configPath}: ${message}` };
  }

  return { ok: true, server, configPath };
}
