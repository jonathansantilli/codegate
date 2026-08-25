import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Where this machine reports to, and the token it presents.
 *
 * Read from the environment first, then from a JSON file in the codegate home
 * directory. The file is the path that matters for a fleet: it can be dropped
 * on every machine by MDM or configuration management without touching a shell
 * profile, which is how 500 laptops get configured.
 */

export const FLEET_CONFIG_FILE = "fleet.json";
export const SERVER_ENV = "CODEGATE_SERVER";
export const TOKEN_ENV = "CODEGATE_TOKEN";

export interface FleetConfig {
  server: string;
  token: string;
}

export type FleetConfigResult = { ok: true; config: FleetConfig } | { ok: false; reason: string };

export interface FleetConfigDeps {
  homeDir?: () => string;
  env?: NodeJS.ProcessEnv;
}

export function fleetConfigPath(deps: FleetConfigDeps = {}): string {
  const home = deps.homeDir ? deps.homeDir() : homedir();
  return join(home, ".codegate", FLEET_CONFIG_FILE);
}

function readConfigFile(path: string): { server?: unknown; token?: unknown } | null {
  if (!existsSync(path)) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    return typeof parsed === "object" && parsed !== null
      ? (parsed as { server?: unknown; token?: unknown })
      : null;
  } catch {
    return null;
  }
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

/**
 * A server must be an absolute http(s) URL. Anything else — a bare hostname, a
 * path, a typo — would fail later inside fetch with a far worse message.
 */
function normalizeServer(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    return url.origin + url.pathname.replace(/\/+$/, "");
  } catch {
    return null;
  }
}

export function resolveFleetConfig(deps: FleetConfigDeps = {}): FleetConfigResult {
  const env = deps.env ?? process.env;
  const path = fleetConfigPath(deps);
  const file = readConfigFile(path);

  const rawServer = asString(env[SERVER_ENV]) ?? asString(file?.server);
  const token = asString(env[TOKEN_ENV]) ?? asString(file?.token);

  if (!rawServer && !token) {
    return {
      ok: false,
      reason: `no Guardian server configured. Set ${SERVER_ENV} and ${TOKEN_ENV}, or write ${path} with {"server": "...", "token": "..."}.`,
    };
  }
  if (!rawServer) {
    return { ok: false, reason: `no server URL. Set ${SERVER_ENV} or "server" in ${path}.` };
  }
  if (!token) {
    return { ok: false, reason: `no token. Set ${TOKEN_ENV} or "token" in ${path}.` };
  }

  const server = normalizeServer(rawServer);
  if (!server) {
    return {
      ok: false,
      reason: `server must be an absolute http(s) URL; got "${rawServer}".`,
    };
  }

  return { ok: true, config: { server, token } };
}
