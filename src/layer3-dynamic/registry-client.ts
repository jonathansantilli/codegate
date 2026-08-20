/**
 * Hardened metadata client for package registries. Constraints, each tested:
 * pinned HTTPS hosts only, redirects rejected, 5s timeout, 1 MiB streamed
 * body cap, JSON only. Returns a typed subset — never the raw registry blob.
 */

export const REGISTRY_KIND = {
  Npm: "npm",
  Pypi: "pypi",
} as const;
export type RegistryKind = (typeof REGISTRY_KIND)[keyof typeof REGISTRY_KIND];

const ALLOWED_HOSTS: Readonly<Record<RegistryKind, string>> = {
  npm: "registry.npmjs.org",
  pypi: "pypi.org",
};

const TIMEOUT_MS = 5000;
const MAX_BODY_BYTES = 1024 * 1024;

export interface RegistryPackageMetadata {
  kind: RegistryKind;
  name: string;
  latestVersion: string | null;
  firstPublishedAt: string | null;
  latestPublishedAt: string | null;
  maintainerCount: number | null;
  deprecated: string | null;
  /** npm lifecycle scripts that run code on install (preinstall/install/postinstall). */
  installScripts: string[];
  repositoryUrl: string | null;
}

export interface RegistryClientDeps {
  fetchImpl?: typeof fetch;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function endpointFor(kind: RegistryKind, name: string): string {
  if (kind === REGISTRY_KIND.Npm) {
    const encoded = name.startsWith("@") ? name.replace(/\//gu, "%2f") : name;
    return `https://${ALLOWED_HOSTS.npm}/${encoded}`;
  }
  return `https://${ALLOWED_HOSTS.pypi}/pypi/${name}/json`;
}

function assertAllowedEndpoint(kind: RegistryKind, endpoint: string): void {
  const url = new URL(endpoint);
  if (url.protocol !== "https:") {
    throw new Error(`Registry endpoint must use https: ${endpoint}`);
  }
  if (url.hostname !== ALLOWED_HOSTS[kind]) {
    throw new Error(`Registry host not allowlisted: ${url.hostname}`);
  }
}

async function readBodyCapped(response: Response): Promise<string> {
  const contentLength = response.headers.get("content-length");
  if (contentLength && Number.parseInt(contentLength, 10) > MAX_BODY_BYTES) {
    throw new Error(`Registry response exceeds ${MAX_BODY_BYTES} bytes`);
  }

  const body = response.body;
  if (!body) {
    const text = await response.text();
    if (text.length > MAX_BODY_BYTES) {
      throw new Error(`Registry response exceeds ${MAX_BODY_BYTES} bytes`);
    }
    return text;
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
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error(`Registry response exceeds ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function fetchRegistryJson(
  kind: RegistryKind,
  name: string,
  deps: RegistryClientDeps,
): Promise<Record<string, unknown>> {
  const endpoint = endpointFor(kind, name);
  assertAllowedEndpoint(kind, endpoint);

  const fetchImpl = deps.fetchImpl ?? fetch;
  const response = await fetchImpl(endpoint, {
    redirect: "error",
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { accept: "application/json" },
  });

  if (!response.ok) {
    throw new Error(`Registry responded with HTTP ${response.status} for ${name}`);
  }

  const raw = await readBodyCapped(response);
  const parsed = JSON.parse(raw) as unknown;
  if (!isRecord(parsed)) {
    throw new Error(`Registry returned a non-object document for ${name}`);
  }
  return parsed;
}

const NPM_INSTALL_SCRIPT_KEYS = ["preinstall", "install", "postinstall"] as const;

function parseNpmMetadata(name: string, doc: Record<string, unknown>): RegistryPackageMetadata {
  const distTags = isRecord(doc["dist-tags"]) ? doc["dist-tags"] : {};
  const latestVersion = typeof distTags.latest === "string" ? distTags.latest : null;
  const time = isRecord(doc.time) ? doc.time : {};
  const versions = isRecord(doc.versions) ? doc.versions : {};
  const latestDoc =
    latestVersion && isRecord(versions[latestVersion]) ? versions[latestVersion] : null;
  const scripts = latestDoc && isRecord(latestDoc.scripts) ? latestDoc.scripts : {};
  const maintainers = Array.isArray(doc.maintainers) ? doc.maintainers : null;
  const repository =
    latestDoc && isRecord(latestDoc.repository)
      ? latestDoc.repository
      : isRecord(doc.repository)
        ? doc.repository
        : null;

  return {
    kind: REGISTRY_KIND.Npm,
    name,
    latestVersion,
    firstPublishedAt: typeof time.created === "string" ? time.created : null,
    latestPublishedAt:
      latestVersion && typeof time[latestVersion] === "string"
        ? (time[latestVersion] as string)
        : null,
    maintainerCount: maintainers ? maintainers.length : null,
    deprecated: latestDoc && typeof latestDoc.deprecated === "string" ? latestDoc.deprecated : null,
    installScripts: NPM_INSTALL_SCRIPT_KEYS.filter((key) => typeof scripts[key] === "string"),
    repositoryUrl: repository && typeof repository.url === "string" ? repository.url : null,
  };
}

function parsePypiMetadata(name: string, doc: Record<string, unknown>): RegistryPackageMetadata {
  const info = isRecord(doc.info) ? doc.info : {};
  const urls = Array.isArray(doc.urls) ? doc.urls : [];
  const firstUpload = urls.find((entry): entry is Record<string, unknown> => isRecord(entry));
  const projectUrls = isRecord(info.project_urls) ? info.project_urls : {};

  return {
    kind: REGISTRY_KIND.Pypi,
    name,
    latestVersion: typeof info.version === "string" ? info.version : null,
    firstPublishedAt: null,
    latestPublishedAt:
      firstUpload && typeof firstUpload.upload_time_iso_8601 === "string"
        ? firstUpload.upload_time_iso_8601
        : null,
    maintainerCount: null,
    deprecated: info.yanked === true ? "yanked" : null,
    installScripts: [],
    repositoryUrl:
      typeof projectUrls.Source === "string"
        ? projectUrls.Source
        : typeof info.home_page === "string" && info.home_page.length > 0
          ? info.home_page
          : null,
  };
}

export async function fetchRegistryMetadata(
  kind: RegistryKind,
  name: string,
  deps: RegistryClientDeps = {},
): Promise<RegistryPackageMetadata> {
  const doc = await fetchRegistryJson(kind, name, deps);
  return kind === REGISTRY_KIND.Npm ? parseNpmMetadata(name, doc) : parsePypiMetadata(name, doc);
}
