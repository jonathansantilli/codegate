import { parseContentBundle, verifyBundleSignature } from "./content-bundle.js";
import {
  getActiveContentVersion,
  listInstalledContentVersions,
  setActiveContentVersion,
  storeContentVersion,
  type ContentStoreDeps,
} from "./content-store.js";
import { CONTENT_PUBLISHER_PUBLIC_KEY_PEM } from "./publisher-key.js";

/**
 * Explicit, user-initiated content updates. Scanning never triggers a
 * fetch; these functions run only from the update-kb/update-rules commands.
 * Integrity comes from the Ed25519 signature (verified before parsing),
 * not from the transport, so release-hosting redirects are acceptable —
 * but the URL must be https.
 */

export const DEFAULT_CONTENT_BASE_URL =
  "https://github.com/jonathansantilli/codegate-content/releases/latest/download";
const BUNDLE_NAME = "codegate-content.json";
const FETCH_TIMEOUT_MS = 15_000;
const MAX_BUNDLE_BYTES = 8 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 4096;

export interface ContentUpdaterDeps extends ContentStoreDeps {
  fetchImpl?: typeof fetch;
}

export interface ContentUpdateOptions {
  baseUrl?: string;
}

function requirePublisherKey(deps: ContentUpdaterDeps): string {
  const key =
    deps.publisherKeyPem !== undefined ? deps.publisherKeyPem : CONTENT_PUBLISHER_PUBLIC_KEY_PEM;
  if (!key) {
    throw new Error(
      "No content publisher key is configured in this build, so remote content cannot be " +
        "verified. Content updates ship with CodeGate releases: npm update -g codegate-ai",
    );
  }
  return key;
}

async function fetchBytes(
  url: string,
  maxBytes: number,
  deps: ContentUpdaterDeps,
): Promise<Buffer> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`Content URL must use https: ${url}`);
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const response = await fetchImpl(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`Content download failed with HTTP ${response.status} for ${url}`);
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
    throw new Error(`Content download exceeds ${maxBytes} bytes: ${url}`);
  }

  const body = response.body;
  if (!body) {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.byteLength > maxBytes) {
      throw new Error(`Content download exceeds ${maxBytes} bytes: ${url}`);
    }
    return buffer;
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`Content download exceeds ${maxBytes} bytes: ${url}`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

interface FetchedBundle {
  bundleBytes: Buffer;
  signature: string;
  version: string;
}

async function fetchAndVerifyBundle(
  deps: ContentUpdaterDeps,
  options: ContentUpdateOptions,
): Promise<FetchedBundle> {
  const key = requirePublisherKey(deps);
  const baseUrl = (options.baseUrl ?? DEFAULT_CONTENT_BASE_URL).replace(/\/+$/u, "");

  const bundleBytes = await fetchBytes(`${baseUrl}/${BUNDLE_NAME}`, MAX_BUNDLE_BYTES, deps);
  const signature = (
    await fetchBytes(`${baseUrl}/${BUNDLE_NAME}.sig`, MAX_SIGNATURE_BYTES, deps)
  ).toString("utf8");

  if (!verifyBundleSignature(bundleBytes, signature, key)) {
    throw new Error(
      "Content bundle signature verification failed. The download was rejected and nothing was installed.",
    );
  }

  // Parse only after the signature proved the bytes came from the publisher.
  const bundle = parseContentBundle(bundleBytes);
  return { bundleBytes, signature, version: bundle.content_version };
}

export interface ContentUpdateResult {
  changed: boolean;
  previousVersion: string | null;
  version: string;
  pruned: string[];
}

export async function updateContent(
  deps: ContentUpdaterDeps = {},
  options: ContentUpdateOptions = {},
): Promise<ContentUpdateResult> {
  const fetched = await fetchAndVerifyBundle(deps, options);
  const previousVersion = getActiveContentVersion(deps);

  if (previousVersion === fetched.version) {
    return { changed: false, previousVersion, version: fetched.version, pruned: [] };
  }

  const bundle = parseContentBundle(fetched.bundleBytes);
  const stored = storeContentVersion(bundle, fetched.bundleBytes, fetched.signature, deps);
  return {
    changed: true,
    previousVersion,
    version: stored.version,
    pruned: stored.pruned,
  };
}

export interface ContentCheckResult {
  currentVersion: string | null;
  remoteVersion: string;
  updateAvailable: boolean;
}

export async function checkContentUpdate(
  deps: ContentUpdaterDeps = {},
  options: ContentUpdateOptions = {},
): Promise<ContentCheckResult> {
  const fetched = await fetchAndVerifyBundle(deps, options);
  const currentVersion = getActiveContentVersion(deps);
  return {
    currentVersion,
    remoteVersion: fetched.version,
    updateAvailable: currentVersion !== fetched.version,
  };
}

export interface ContentRollbackResult {
  version: string;
}

export function rollbackContent(deps: ContentUpdaterDeps = {}): ContentRollbackResult {
  const installed = listInstalledContentVersions(deps);
  const active = getActiveContentVersion(deps);
  const candidates = installed.filter((entry) => entry.version !== active);
  const target = candidates[0];
  if (!target) {
    throw new Error("No previous content version is installed to roll back to.");
  }
  setActiveContentVersion(target.version, deps);
  return { version: target.version };
}
