import type { RuntimeMode } from "../config.js";
import type { DeepScanResource } from "../pipeline.js";
import {
  fetchRegistryMetadata,
  REGISTRY_KIND,
  type RegistryClientDeps,
  type RegistryKind,
} from "./registry-client.js";
import type { ResourceFetchResult } from "./resource-fetcher.js";

export interface DeepResourceExecutionContext {
  runtimeMode?: RuntimeMode;
}

function registryKindFor(resource: DeepScanResource): RegistryKind | null {
  if (resource.request.kind === "npm") {
    return REGISTRY_KIND.Npm;
  }
  if (resource.request.kind === "pypi") {
    return REGISTRY_KIND.Pypi;
  }
  return null;
}

function recordOnlyResult(resource: DeepScanResource): ResourceFetchResult {
  return {
    status: "ok",
    attempts: 0,
    elapsedMs: 0,
    metadata: {
      resource_id: resource.id,
      resource_kind: resource.request.kind,
      resource_url: resource.request.locator,
      note: "URL recorded for analysis without making outbound connections.",
    },
  };
}

function classifyError(error: unknown): ResourceFetchResult["status"] {
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  if (message.includes("timeout") || message.includes("abort")) {
    return "timeout";
  }
  return "network_error";
}

/**
 * Default deep-resource executor.
 *
 * URL resources (http/sse) are never fetched: connecting to endpoints found
 * in scanned config files is a security risk (crafted responses, SSRF, IP
 * logging), so the URL is recorded as metadata for the agent to analyze.
 *
 * npm/pypi package resources are different: their metadata comes from
 * pinned, well-known registry hosts, not from attacker-chosen endpoints.
 * When the runtime mode is "online" (and the per-resource consent the
 * caller already collected), the hardened registry client fetches a typed
 * metadata subset. Offline (the default) stays record-only.
 */
export function createDeepResourceExecutor(deps: RegistryClientDeps = {}) {
  return async (
    resource: DeepScanResource,
    context?: DeepResourceExecutionContext,
  ): Promise<ResourceFetchResult> => {
    const registryKind = registryKindFor(resource);
    if (!registryKind || context?.runtimeMode !== "online") {
      return recordOnlyResult(resource);
    }

    const startedAt = Date.now();
    try {
      const registry = await fetchRegistryMetadata(registryKind, resource.request.locator, deps);
      return {
        status: "ok",
        attempts: 1,
        elapsedMs: Date.now() - startedAt,
        metadata: {
          resource_id: resource.id,
          resource_kind: resource.request.kind,
          registry,
        },
      };
    } catch (error) {
      return {
        status: classifyError(error),
        attempts: 1,
        elapsedMs: Date.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  };
}
