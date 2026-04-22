/**
 * URL validation and normalisation helpers for Layer 3 remote resource handling.
 *
 * These helpers guarantee that remote resources (HTTP/SSE MCP endpoints,
 * skill-referenced URLs) use a safe, canonical form before they are fed into
 * finding `rule_id` / `file_path` fields or into the fetcher.
 *
 * Historically, L3 resource IDs were composed as `${kind}:${url}` which, for
 * http/sse kinds, produced malformed values like `http:https://mcp.linear.app/mcp`
 * (the kind collides with the URL's own scheme). `buildResourceId` avoids that
 * double-scheme shape by reusing the URL itself as the id for http/sse kinds.
 */
export type RemoteScheme = "http" | "https";

export interface NormalizeRemoteUrlResult {
  ok: true;
  url: string;
  scheme: RemoteScheme;
}

export interface NormalizeRemoteUrlError {
  ok: false;
  reason: "empty" | "unsupported_scheme" | "missing_host" | "missing_scheme" | "invalid_url";
}

/**
 * Validate and canonicalise a remote URL. Rejects non http/https schemes,
 * missing hosts, and malformed inputs. Normalises a bare-host path to a
 * single trailing slash and strips trailing slashes from longer paths.
 */
export function normalizeRemoteUrl(
  input: string,
): NormalizeRemoteUrlResult | NormalizeRemoteUrlError {
  if (typeof input !== "string" || input.trim().length === 0) {
    return { ok: false, reason: "empty" };
  }

  const trimmed = input.trim();

  // Quick reject for bare `http:` / `https:` without `//` and host.
  if (/^https?:\/?$/iu.test(trimmed)) {
    return { ok: false, reason: "missing_host" };
  }

  // Must start with http:// or https:// (case-insensitive).
  if (!/^https?:\/\//iu.test(trimmed)) {
    return { ok: false, reason: "missing_scheme" };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { ok: false, reason: "invalid_url" };
  }

  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  if (scheme !== "http" && scheme !== "https") {
    return { ok: false, reason: "unsupported_scheme" };
  }

  if (parsed.hostname.length === 0) {
    return { ok: false, reason: "missing_host" };
  }

  // Normalise trailing slashes: keep `/` for root paths, strip for others.
  if (parsed.pathname.length > 1 && parsed.pathname.endsWith("/")) {
    parsed.pathname = parsed.pathname.replace(/\/+$/u, "");
  }

  return {
    ok: true,
    url: parsed.toString(),
    scheme: scheme as RemoteScheme,
  };
}

export type DeepScanResourceKind = "npm" | "pypi" | "git" | "http" | "sse";

/**
 * Build a canonical resource id used for findings (`rule_id`, `file_path`) and
 * for consent prompts. For http/sse kinds the id is the URL itself (no
 * `http:` / `sse:` prefix) to avoid the malformed `http:https://...` shape.
 * For npm/pypi/git, the `<kind>:<locator>` prefix is preserved because those
 * locators are not URLs and other code (e.g. `isRegistryMetadataResource`)
 * keys on that prefix.
 */
export function buildResourceId(kind: DeepScanResourceKind, locator: string): string {
  if (kind === "http" || kind === "sse") {
    return locator;
  }
  return `${kind}:${locator}`;
}
