import {
  fetchResourceMetadata,
  type ResourceFetchResult,
  type ResourceKind,
  type ResourceRequest,
} from "./resource-fetcher.js";

export interface AcquiredToolDescription {
  name: string;
  description: string;
}

export interface ToolDescriptionCandidate {
  serverId: string;
  transport: "stdio" | "http" | "sse";
  command?: string[];
  url?: string;
  sourceTools?: AcquiredToolDescription[];
}

export type ToolDescriptionAcquisitionStatus =
  | "ok"
  | "auth_failure"
  | "timeout"
  | "network_error"
  | "command_error"
  | "rejected_unsafe_stdio"
  | "schema_mismatch";

export interface ToolDescriptionAcquisitionResult {
  status: ToolDescriptionAcquisitionStatus;
  tools: AcquiredToolDescription[];
  error?: string;
}

export interface ToolDescriptionAcquisitionDeps {
  fetchMetadata: (request: ResourceRequest) => Promise<ResourceFetchResult>;
}

function defaultDeps(): ToolDescriptionAcquisitionDeps {
  return {
    fetchMetadata: async (request) => fetchResourceMetadata(request),
  };
}

function parseTools(metadata: unknown): AcquiredToolDescription[] {
  if (!metadata || typeof metadata !== "object") {
    return [];
  }
  const root = metadata as Record<string, unknown>;
  if (!Array.isArray(root.tools)) {
    return [];
  }

  return root.tools
    .filter((entry): entry is Record<string, unknown> => typeof entry === "object" && entry !== null)
    .map((entry) => ({
      name: typeof entry.name === "string" ? entry.name : "",
      description: typeof entry.description === "string" ? entry.description : "",
    }))
    .filter((entry) => entry.name.length > 0 && entry.description.length > 0);
}

function requestFromCandidate(candidate: ToolDescriptionCandidate): ResourceRequest | null {
  if (!candidate.url) {
    return null;
  }
  const kind: ResourceKind = candidate.transport === "sse" ? "sse" : "http";
  return {
    id: `${kind}:${candidate.serverId}`,
    kind,
    locator: candidate.url,
  };
}

export async function acquireToolDescriptions(
  candidate: ToolDescriptionCandidate,
  customDeps: ToolDescriptionAcquisitionDeps = defaultDeps(),
): Promise<ToolDescriptionAcquisitionResult> {
  if (candidate.transport === "stdio") {
    if (candidate.sourceTools && candidate.sourceTools.length > 0) {
      return {
        status: "ok",
        tools: candidate.sourceTools,
      };
    }
    return {
      status: "rejected_unsafe_stdio",
      tools: [],
      error: "stdio execution is not allowed for tool-description acquisition",
    };
  }

  const request = requestFromCandidate(candidate);
  if (!request) {
    return {
      status: "schema_mismatch",
      tools: [],
      error: "missing remote endpoint URL",
    };
  }

  const response = await customDeps.fetchMetadata(request);
  if (response.status !== "ok") {
    return {
      status: response.status,
      tools: [],
      error: response.error,
    };
  }

  const tools = parseTools(response.metadata);
  if (tools.length === 0) {
    return {
      status: "schema_mismatch",
      tools: [],
      error: "metadata did not include tools[] with name and description",
    };
  }

  return {
    status: "ok",
    tools,
  };
}
