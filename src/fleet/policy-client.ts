import type { FleetConfig } from "./fleet-config.js";
import {
  COLLECT_NOTHING,
  resolveCollectionPolicy,
  type EffectiveCollectionPolicy,
} from "./collection-policy.js";

/**
 * Asks a Guardian server what it is willing to be sent.
 *
 * Fails closed, in every direction. A server that is unreachable, slow, broken,
 * or answering with something that is not the JSON we expected gets the same
 * answer as a server that said no: send nothing. There is deliberately no path
 * through this file where a failure results in MORE being sent — the worst a
 * broken policy read can do is make a check-in carry what it has always
 * carried, which is hashes and findings.
 *
 * A failure here is never fatal to the check-in either. Reporting inventory is
 * the job; content is an extra the server may or may not want, and a machine
 * that cannot read the policy still has something worth saying.
 */

export const POLICY_PATH = "/api/agent/policy";
const DEFAULT_TIMEOUT_MS = 10_000;
/** A policy document is small. Anything larger is not one. */
const MAX_POLICY_BYTES = 64 * 1024;

export interface FetchPolicyDeps {
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
}

export async function fetchCollectionPolicy(
  config: FleetConfig,
  deps: FetchPolicyDeps = {},
): Promise<EffectiveCollectionPolicy> {
  const doFetch = deps.fetch ?? globalThis.fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), deps.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  try {
    const response = await doFetch(`${config.server}${POLICY_PATH}`, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${config.token}`,
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      return COLLECT_NOTHING;
    }

    // An older Guardian has no policy endpoint and its 404 lands above. A
    // proxy or captive portal answering HTML with a 200 lands here.
    const body = await response.text();
    if (body.length > MAX_POLICY_BYTES) {
      return COLLECT_NOTHING;
    }

    return resolveCollectionPolicy(JSON.parse(body) as Record<string, unknown>);
  } catch {
    return COLLECT_NOTHING;
  } finally {
    clearTimeout(timeout);
  }
}
