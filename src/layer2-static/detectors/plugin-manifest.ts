import type { Finding } from "../../types/finding.js";
import { buildFindingEvidence, type FindingEvidence } from "../evidence.js";

export interface PluginManifestInput {
  filePath: string;
  parsed: unknown;
  textContent: string;
  trustedApiDomains: string[];
  blockedCommands: string[];
}

const SHELL_META_PATTERN = /[|;&`]|[$][(]/u;
const NETWORK_UTILITY_PATTERN = /\b(curl|wget|nc|ncat|socat)\b/iu;

const SOURCE_KEYS = new Set([
  "source",
  "url",
  "serviceurl",
  "itemurl",
  "resourceurltemplate",
  "recommendationsurl",
  "nlsbaseurl",
  "publisherurl",
  "cacheurl",
  "controlurl",
  "downloadurl",
  "downloaduri",
  "registry",
  "repository",
  "packageurl",
  "packageuri",
  "image",
  "installfrom",
]);
const IMAGE_KEYS = new Set(["image", "containerimage", "dockerimage"]);
const INTEGRITY_KEYS = new Set([
  "sha256",
  "sha512",
  "checksum",
  "integrity",
  "digest",
  "hash",
  "shasum",
]);

const INSTALL_SCRIPT_KEYS = new Set([
  "postinstall",
  "preinstall",
  "installscript",
  "setupcommand",
  "installcommand",
  "oninstall",
]);
const PERMISSION_KEYS = new Set([
  "permissions",
  "permission",
  "capabilities",
  "capability",
  "scopes",
  "scope",
  "grants",
  "allowedcapabilities",
  "enabledcapabilities",
  "toolpermissions",
  "toolpermission",
]);
const UNVERIFIED_PUBLISHER_KEYS = new Set([
  "publisherverified",
  "publishertrusted",
  "trustedpublisher",
  "isverified",
  "verified",
  "signatureverified",
  "signaturevalid",
]);
const SIGNATURE_BYPASS_KEYS = new Set([
  "allowunsigned",
  "allowunverified",
  "skipverification",
  "skipverifications",
  "skipsignature",
  "skipsignaturecheck",
  "skipsignatureverification",
  "ignoresignature",
  "ignorechecksum",
  "ignorechecksums",
  "disableverification",
  "disablesignatureverification",
]);
const PUBLISHER_TRUST_BYPASS_KEYS = new Set([
  "allowuntrustedpublishers",
  "allowunknownpublishers",
  "allowunverifiedpublishers",
  "skippublisherverification",
  "disablepublisherverification",
  "bypasspublishertrust",
  "ignorepublishertrust",
]);
const PUBLISHER_TRUST_DISABLED_KEYS = new Set([
  "trustedpublishersonly",
  "requireverifiedpublisher",
  "enforcepublisherverification",
]);
const VSCODE_RECOMMENDATION_KEYS = new Set(["recommendations", "unwantedrecommendations"]);
const VERSION_FIELD_KEYS = new Set([
  "version",
  "pluginversion",
  "extensionversion",
  "packageversion",
  "targetversion",
  "requiredversion",
]);
const PACKAGE_IDENTITY_KEYS = new Set([
  "id",
  "name",
  "slug",
  "package",
  "packagename",
  "extension",
  "extensionid",
  "plugin",
  "pluginid",
  "artifactid",
]);
const DISALLOWED_NAMESPACE_TOKENS = new Set([
  "local",
  "localhost",
  "temp",
  "tmp",
  "test",
  "example",
  "sample",
  "demo",
  "unknown",
]);
const UNPINNED_VERSION_TOKENS = new Set([
  "latest",
  "stable",
  "next",
  "nightly",
  "canary",
  "alpha",
  "beta",
  "preview",
  "insiders",
  "dev",
  "edge",
  "main",
  "master",
  "head",
  "*",
  "x",
]);
const TRANSPARENCY_BYPASS_KEYS = new Set([
  "allowmissingtlog",
  "allowmissingtransparencyproof",
  "allowmissingtransparencylog",
  "skiptlogverification",
  "skiprekorverification",
  "skiptransparencyverification",
  "skiptransparencylogverification",
  "ignoretlog",
  "ignorerekor",
  "disabletlogverification",
  "disabletransparencyverification",
  "disabletransparencylog",
  "bypasstransparencylog",
  "nologverification",
  "notransparencyverification",
]);
const ATTESTATION_KEYS = new Set([
  "attestation",
  "attestations",
  "provenance",
  "buildprovenance",
  "supplychainprovenance",
  "slsa",
  "sigstore",
  "cosign",
  "signedattestation",
  "attestationstatus",
  "provenancestatus",
]);
const RELEASE_CHANNEL_KEYS = new Set([
  "releasechannel",
  "channel",
  "track",
  "stream",
  "ring",
  "updatechannel",
  "distributionchannel",
  "releasetrack",
]);
const PRERELEASE_FLAG_KEYS = new Set([
  "allowprerelease",
  "includeprerelease",
  "useprerelease",
  "prerelease",
  "enableprerelease",
  "preview",
  "insiders",
  "nightly",
]);
const UNSTABLE_RELEASE_CHANNEL_TOKENS = new Set([
  "nightly",
  "canary",
  "alpha",
  "beta",
  "preview",
  "insiders",
  "dev",
  "edge",
  "experimental",
  "next",
  "prerelease",
  "rc",
]);
const ATTESTATION_ISSUER_FIELD_KEYS = new Set([
  "issuer",
  "oidcissuer",
  "identityissuer",
  "certificateissuer",
  "signerissuer",
  "fulcioissuer",
  "trustanchorissuer",
  "attestationissuer",
]);
const ATTESTATION_SUBJECT_FIELD_KEYS = new Set([
  "subject",
  "subjects",
  "artifact",
  "artifactid",
  "artifactdigest",
  "digest",
  "package",
  "packageurl",
  "uri",
  "name",
  "version",
  "material",
]);
const ATTESTATION_DIGEST_FIELD_KEYS = new Set([
  "digest",
  "artifactdigest",
  "sha256",
  "sha512",
  "checksum",
  "integrity",
  "hash",
]);
const ATTESTATION_VERIFICATION_FIELD_KEYS = new Set([
  "verified",
  "verification",
  "verificationstatus",
  "status",
  "result",
  "valid",
  "signatureverified",
  "signaturevalid",
]);
const ATTESTATION_CERT_CHAIN_CONTEXT_KEYS = new Set([
  "certificate",
  "cert",
  "x5c",
  "chain",
  "rootca",
  "intermediate",
  "trustanchor",
]);
const ATTESTATION_TRANSPARENCY_CONTEXT_KEYS = new Set([
  "transparency",
  "tlog",
  "rekor",
  "inclusion",
  "checkpoint",
  "integratedtime",
  "signedentrytimestamp",
  "logentry",
  "logproof",
]);
const ATTESTATION_TRANSPARENCY_FIELD_KEYS = new Set([
  "transparencylog",
  "tlog",
  "rekor",
  "inclusionproof",
  "inclusionpromise",
  "logproof",
  "logentry",
  "logindex",
  "entryuuid",
  "uuid",
  "checkpoint",
  "integratedtime",
  "signedentrytimestamp",
]);
const TRUSTED_ATTESTATION_ISSUER_DOMAINS = new Set([
  "token.actions.githubusercontent.com",
  "oauth2.sigstore.dev",
  "fulcio.sigstore.dev",
  "accounts.google.com",
  "gitlab.com",
  "login.microsoftonline.com",
  "sts.windows.net",
]);

interface AttestationRequiredField {
  label: string;
  keys: Set<string>;
}

interface AttestationProfile {
  id: string;
  schemaProfile: "base" | "strict";
  trustedIssuerDomains: string[];
  requiredFields: AttestationRequiredField[];
  requireTransparencyProof: boolean;
  enforceCertificatePolicy: boolean;
}

const BASE_ATTESTATION_REQUIRED_FIELDS: AttestationRequiredField[] = [
  { label: "issuer", keys: ATTESTATION_ISSUER_FIELD_KEYS },
  { label: "subject", keys: ATTESTATION_SUBJECT_FIELD_KEYS },
  { label: "verification_status", keys: ATTESTATION_VERIFICATION_FIELD_KEYS },
];

const STRICT_ATTESTATION_REQUIRED_FIELDS: AttestationRequiredField[] = [
  ...BASE_ATTESTATION_REQUIRED_FIELDS,
  { label: "digest", keys: ATTESTATION_DIGEST_FIELD_KEYS },
];
const CERT_POLICY_FIELD_MARKERS = [
  "extendedkeyusage",
  "eku",
  "keyusage",
  "usage",
  "certificatepolicy",
  "certificatepolicies",
  "policyoid",
  "policyoids",
  "oid",
  "oids",
];
const CODE_SIGNING_POLICY_TOKENS = new Set([
  "1.3.6.1.5.5.7.3.3",
  "136155733",
  "codesigning",
  "codesign",
  "idkpcodesigning",
  "id-kp-codesigning",
]);
const TRANSPARENCY_LOG_INDEX_KEY_MARKERS = ["logindex", "entryindex", "index"];
const TRANSPARENCY_TREE_SIZE_KEY_MARKERS = ["treesize", "logsize"];
const TRANSPARENCY_INTEGRATED_TIME_KEY_MARKERS = ["integratedtime"];
const TRANSPARENCY_FUTURE_SKEW_SECONDS = 24 * 60 * 60;

const WILDCARD_PERMISSION_TOKENS = new Set([
  "*",
  "all",
  "any",
  "allpermissions",
  "allcapabilities",
  "fullaccess",
  "unrestricted",
  "allowall",
]);

const RISKY_CAPABILITY_TOKENS = [
  "shell",
  "exec",
  "execute",
  "terminal",
  "command",
  "spawn",
  "filesystemwrite",
  "filewrite",
  "writefilesystem",
  "network",
  "outbound",
  "internet",
  "env",
  "secret",
  "credential",
  "system",
];

const TRUSTED_SOURCE_DOMAINS = new Set([
  "registry.npmjs.org",
  "npmjs.com",
  "www.npmjs.com",
  "pypi.org",
  "github.com",
  "raw.githubusercontent.com",
  "plugins.jetbrains.com",
  "open-vsx.org",
  "marketplace.visualstudio.com",
  "zed.dev",
  "marketplace.roocode.com",
  "roocode.com",
  "registry.opencode.ai",
  "opencode.ai",
]);
const MARKETPLACE_ANCHOR_DOMAINS = new Set([
  "marketplace.visualstudio.com",
  "open-vsx.org",
  "plugins.jetbrains.com",
  "zed.dev",
  "marketplace.roocode.com",
  "roocode.com",
  "registry.opencode.ai",
  "opencode.ai",
]);
const USER_SCOPE_ADVISORY_RULE_IDS = new Set([
  "plugin-manifest-untrusted-source-url",
  "plugin-manifest-cross-marketplace-source",
  "plugin-manifest-missing-integrity",
  "plugin-manifest-missing-package-identity",
  "plugin-manifest-unpinned-version",
  "plugin-manifest-unpinned-git-source",
  "plugin-manifest-unpinned-image",
  "plugin-manifest-versioned-extension-id",
  "plugin-manifest-unscoped-extension-id",
  "plugin-manifest-missing-marketplace-provenance",
  "plugin-manifest-nonallowlisted-extension-registry",
  "plugin-manifest-extension-registry-host-mismatch",
  "plugin-manifest-disallowed-namespace",
  "plugin-manifest-unstable-release-channel",
]);
const SEVERITY_ORDER: Finding["severity"][] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const KIRO_EXTENSION_REGISTRY_URL_KEYS = new Set([
  "serviceurl",
  "itemurl",
  "resourceurltemplate",
  "controlurl",
  "recommendationsurl",
  "nlsbaseurl",
  "publisherurl",
  "cacheurl",
]);
const TRUSTED_KIRO_EXTENSION_REGISTRY_DOMAINS = new Set(["open-vsx.org"]);

interface MarketplaceSourcePolicy {
  id: string;
  allowedMarketplaceDomains: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeKey(key: string): string {
  return key.replace(/[^a-z0-9]/giu, "").toLowerCase();
}

function shouldInspectFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    lower.includes("plugins.json") ||
    lower.includes("extensions.json") ||
    lower.includes("marketplace.json") ||
    isKiroProductManifest(lower)
  );
}

function isTrustedSourceDomain(hostname: string, trustedApiDomains: string[]): boolean {
  const lower = hostname.toLowerCase();
  for (const domain of [
    ...TRUSTED_SOURCE_DOMAINS,
    ...trustedApiDomains.map((value) => value.toLowerCase()),
  ]) {
    if (lower === domain || lower.endsWith(`.${domain}`)) {
      return true;
    }
  }
  return false;
}

function matchesDomain(hostname: string, domain: string): boolean {
  const lowerHost = hostname.toLowerCase();
  const lowerDomain = domain.toLowerCase();
  return lowerHost === lowerDomain || lowerHost.endsWith(`.${lowerDomain}`);
}

function isMarketplaceAnchorDomain(hostname: string): boolean {
  for (const domain of MARKETPLACE_ANCHOR_DOMAINS) {
    if (matchesDomain(hostname, domain)) {
      return true;
    }
  }
  return false;
}

function isUserTrustedDomain(hostname: string, trustedApiDomains: string[]): boolean {
  for (const domain of trustedApiDomains) {
    if (matchesDomain(hostname, domain)) {
      return true;
    }
  }
  return false;
}

function isAllowedByMarketplacePolicy(hostname: string, policy: MarketplaceSourcePolicy): boolean {
  return policy.allowedMarketplaceDomains.some((domain) => matchesDomain(hostname, domain));
}

function isTrustedKiroExtensionRegistryDomain(
  hostname: string,
  trustedApiDomains: string[],
): boolean {
  for (const domain of [...TRUSTED_KIRO_EXTENSION_REGISTRY_DOMAINS, ...trustedApiDomains]) {
    if (matchesDomain(hostname, domain)) {
      return true;
    }
  }
  return false;
}

function requiresMarketplaceProvenance(policy: MarketplaceSourcePolicy): boolean {
  return (
    policy.id === "roo" ||
    policy.id === "opencode" ||
    policy.id === "zed" ||
    policy.id === "claude" ||
    policy.id === "gemini"
  );
}

function parseSourceUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isKiroExtensionRegistryField(
  filePath: string,
  normalizedKey: string,
  path: string,
): boolean {
  if (!isKiroProductManifest(filePath)) {
    return false;
  }
  if (!KIRO_EXTENSION_REGISTRY_URL_KEYS.has(normalizedKey)) {
    return false;
  }
  return normalizeKey(path).includes("extensionsgallery");
}

function isLocalSourcePath(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.startsWith("./") ||
    normalized.startsWith("../") ||
    normalized.startsWith("/") ||
    normalized.startsWith("~/") ||
    normalized.startsWith("file:") ||
    /^[a-z]:\\/iu.test(value) ||
    normalized.startsWith("..\\") ||
    normalized.startsWith(".\\")
  );
}

function isImageReference(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0 || /^[a-z][a-z0-9+.-]*:\/\//iu.test(trimmed)) {
    return false;
  }
  return trimmed.includes("/") || trimmed.includes(":");
}

function isDigestPinnedImage(value: string): boolean {
  return /@sha256:[0-9a-f]{64}$/iu.test(value.trim());
}

function isLikelyGitSource(value: string, parsedUrl: URL | null): boolean {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.startsWith("git+")) {
    return true;
  }
  if (trimmed.endsWith(".git") || trimmed.includes(".git#")) {
    return true;
  }
  if (!parsedUrl) {
    return false;
  }
  const host = parsedUrl.hostname.toLowerCase();
  const isGithub =
    host === "github.com" || host.endsWith(".github.com");
  const isGitlab =
    host === "gitlab.com" || host.endsWith(".gitlab.com");
  const isBitbucket =
    host === "bitbucket.org" || host.endsWith(".bitbucket.org");
  return isGithub || isGitlab || isBitbucket;
}

function hasPinnedGitCommit(value: string, parsedUrl: URL | null): boolean {
  const fragment = parsedUrl?.hash ? parsedUrl.hash.slice(1) : "";
  if (/^[0-9a-f]{7,40}$/iu.test(fragment)) {
    return true;
  }
  const queryRef = parsedUrl?.searchParams.get("ref");
  if (queryRef && /^[0-9a-f]{7,40}$/iu.test(queryRef)) {
    return true;
  }
  return /(?:#|[?&]ref=)([0-9a-f]{7,40})\b/iu.test(value);
}

function isArtifactSourceUrl(parsedUrl: URL): boolean {
  const lowerPath = parsedUrl.pathname.toLowerCase();
  if (lowerPath.includes("/releases/download/")) {
    return true;
  }

  return [".tgz", ".tar.gz", ".tar", ".zip", ".vsix", ".whl", ".jar", ".gz", ".bz2", ".xz"].some(
    (suffix) => lowerPath.endsWith(suffix),
  );
}

function permissionTokensFromString(value: string): string[] {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return [];
  }

  const tokens = new Set<string>();
  tokens.add(normalizeKey(trimmed));
  if (trimmed === "*") {
    tokens.add("*");
  }

  for (const part of trimmed.split(/[\s,;|/]+/u)) {
    const normalized = normalizeKey(part);
    if (normalized.length > 0) {
      tokens.add(normalized);
    }
    if (part.trim() === "*") {
      tokens.add("*");
    }
  }

  return Array.from(tokens);
}

function collectPermissionTokens(value: unknown): string[] {
  const tokens = new Set<string>();

  function visit(candidate: unknown): void {
    if (typeof candidate === "string") {
      for (const token of permissionTokensFromString(candidate)) {
        tokens.add(token);
      }
      return;
    }
    if (Array.isArray(candidate)) {
      for (const entry of candidate) {
        visit(entry);
      }
      return;
    }
    if (!isRecord(candidate)) {
      return;
    }

    for (const [key, entry] of Object.entries(candidate)) {
      const keyToken = normalizeKey(key);
      if (typeof entry === "boolean") {
        if (entry) {
          tokens.add(keyToken);
        }
        continue;
      }
      if (typeof entry === "number") {
        if (entry > 0) {
          tokens.add(keyToken);
        }
        continue;
      }
      if (typeof entry === "string") {
        if (entry.trim().length > 0) {
          tokens.add(keyToken);
          for (const token of permissionTokensFromString(entry)) {
            tokens.add(token);
          }
        }
        continue;
      }
      visit(entry);
    }
  }

  visit(value);
  return Array.from(tokens);
}

function findWildcardPermissionTokens(tokens: string[]): string[] {
  return tokens.filter((token) => WILDCARD_PERMISSION_TOKENS.has(token));
}

function findRiskyCapabilityTokens(tokens: string[]): string[] {
  return tokens.filter((token) => RISKY_CAPABILITY_TOKENS.some((marker) => token.includes(marker)));
}

function isAffirmative(value: unknown): boolean {
  if (value === true) {
    return true;
  }
  if (typeof value === "number") {
    return value > 0;
  }
  if (typeof value === "string") {
    return ["true", "yes", "on", "enabled", "enable", "1"].includes(value.trim().toLowerCase());
  }
  return false;
}

function isExplicitlyUnverified(value: unknown): boolean {
  if (value === false || value === null) {
    return true;
  }
  if (typeof value === "string") {
    return ["false", "no", "unverified", "unknown", "none", "invalid"].includes(
      value.trim().toLowerCase(),
    );
  }
  return false;
}

function isVsCodeExtensionsManifest(filePath: string): boolean {
  return filePath.toLowerCase().endsWith(".vscode/extensions.json");
}

function isOpencodePluginManifest(filePath: string): boolean {
  return filePath.toLowerCase().endsWith(".opencode/plugins.json");
}

function isClaudePluginManifest(filePath: string): boolean {
  return filePath.toLowerCase().endsWith(".claude/plugins.json");
}

function isZedExtensionsManifest(filePath: string): boolean {
  return filePath.toLowerCase().endsWith(".zed/extensions.json");
}

function isGeminiExtensionsManifest(filePath: string): boolean {
  return filePath.toLowerCase().endsWith(".gemini/extensions.json");
}

function isRooMarketplaceManifest(filePath: string): boolean {
  return filePath.toLowerCase().endsWith(".roo/marketplace.json");
}

function isClineMarketplaceManifest(filePath: string): boolean {
  return filePath.toLowerCase().endsWith(".cline/marketplace.json");
}

function isKiroProductManifest(filePath: string): boolean {
  return filePath.toLowerCase().endsWith(".kiro/product.json");
}

function isMarketplaceSemanticsManifest(filePath: string): boolean {
  return (
    isVsCodeExtensionsManifest(filePath) ||
    isClaudePluginManifest(filePath) ||
    isOpencodePluginManifest(filePath) ||
    isGeminiExtensionsManifest(filePath) ||
    isZedExtensionsManifest(filePath) ||
    isRooMarketplaceManifest(filePath) ||
    isClineMarketplaceManifest(filePath)
  );
}

function marketplaceSourcePolicyForFile(filePath: string): MarketplaceSourcePolicy | null {
  if (isVsCodeExtensionsManifest(filePath)) {
    return {
      id: "vscode",
      allowedMarketplaceDomains: ["marketplace.visualstudio.com", "open-vsx.org"],
    };
  }
  if (isClaudePluginManifest(filePath)) {
    return {
      id: "claude",
      allowedMarketplaceDomains: ["registry.npmjs.org", "npmjs.com", "www.npmjs.com", "github.com"],
    };
  }
  if (isOpencodePluginManifest(filePath)) {
    return {
      id: "opencode",
      allowedMarketplaceDomains: ["registry.opencode.ai", "opencode.ai"],
    };
  }
  if (isGeminiExtensionsManifest(filePath)) {
    return {
      id: "gemini",
      allowedMarketplaceDomains: ["registry.npmjs.org", "npmjs.com", "www.npmjs.com", "github.com"],
    };
  }
  if (isZedExtensionsManifest(filePath)) {
    return {
      id: "zed",
      allowedMarketplaceDomains: ["zed.dev"],
    };
  }
  if (isRooMarketplaceManifest(filePath)) {
    return {
      id: "roo",
      allowedMarketplaceDomains: ["marketplace.roocode.com", "roocode.com"],
    };
  }
  if (isClineMarketplaceManifest(filePath)) {
    return {
      id: "cline",
      allowedMarketplaceDomains: ["open-vsx.org", "marketplace.visualstudio.com"],
    };
  }
  return null;
}

function isScopedVsCodeExtensionId(value: string): boolean {
  return /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*$/iu.test(value.trim());
}

function isPathTraversalLike(value: string): boolean {
  return /(^|[\\/])\.\.([\\/]|$)/u.test(value);
}

function isInvalidPackageIdentity(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return true;
  }
  if (parseSourceUrl(trimmed)) {
    return true;
  }
  if (isLocalSourcePath(trimmed)) {
    return true;
  }
  if (trimmed.startsWith("git+") || trimmed.startsWith("ssh://")) {
    return true;
  }
  if (trimmed.includes("\\") || /\s/u.test(trimmed)) {
    return true;
  }
  if (isPathTraversalLike(trimmed)) {
    return true;
  }
  return false;
}

function isInvalidVsCodeRecommendationEntry(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return false;
  }
  if (isScopedVsCodeExtensionId(trimmed) || parseVsCodeVersionQualifiedId(trimmed)) {
    return false;
  }
  if (parseSourceUrl(trimmed)) {
    return true;
  }
  if (isLocalSourcePath(trimmed) || isPathTraversalLike(trimmed)) {
    return true;
  }
  if (trimmed.startsWith("git+") || trimmed.startsWith("ssh://")) {
    return true;
  }
  if (trimmed.includes("/") || trimmed.includes("\\") || trimmed.includes(":")) {
    return true;
  }
  return false;
}

function namespaceTokenFromIdentity(value: string, filePath: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }

  if (isVsCodeExtensionsManifest(filePath)) {
    if (!isScopedVsCodeExtensionId(trimmed)) {
      return null;
    }
    return trimmed.split(".")[0]?.toLowerCase() ?? null;
  }

  if (trimmed.startsWith("@")) {
    const slashIndex = trimmed.indexOf("/");
    if (slashIndex > 1) {
      return trimmed.slice(1, slashIndex).toLowerCase();
    }
  }

  const slashIndex = trimmed.indexOf("/");
  if (slashIndex > 0) {
    return trimmed.slice(0, slashIndex).toLowerCase();
  }

  const dotIndex = trimmed.indexOf(".");
  if (dotIndex > 0) {
    return trimmed.slice(0, dotIndex).toLowerCase();
  }

  return trimmed.toLowerCase();
}

function isDisallowedNamespace(value: string, filePath: string): boolean {
  const namespace = namespaceTokenFromIdentity(value, filePath);
  if (!namespace) {
    return false;
  }
  return DISALLOWED_NAMESPACE_TOKENS.has(namespace);
}

function attestationProfileForFile(filePath: string): AttestationProfile {
  if (isVsCodeExtensionsManifest(filePath)) {
    return {
      id: "vscode",
      schemaProfile: "strict",
      trustedIssuerDomains: [
        ...Array.from(TRUSTED_ATTESTATION_ISSUER_DOMAINS),
        "vstoken.dev.azure.com",
        "dev.azure.com",
        "visualstudio.com",
        "microsoft.com",
      ],
      requiredFields: STRICT_ATTESTATION_REQUIRED_FIELDS,
      requireTransparencyProof: true,
      enforceCertificatePolicy: true,
    };
  }

  if (isOpencodePluginManifest(filePath)) {
    return {
      id: "opencode",
      schemaProfile: "base",
      trustedIssuerDomains: [
        ...Array.from(TRUSTED_ATTESTATION_ISSUER_DOMAINS),
        "registry.opencode.ai",
        "opencode.ai",
      ],
      requiredFields: BASE_ATTESTATION_REQUIRED_FIELDS,
      requireTransparencyProof: false,
      enforceCertificatePolicy: false,
    };
  }

  if (isClaudePluginManifest(filePath)) {
    return {
      id: "claude",
      schemaProfile: "base",
      trustedIssuerDomains: [
        ...Array.from(TRUSTED_ATTESTATION_ISSUER_DOMAINS),
        "registry.npmjs.org",
        "npmjs.com",
      ],
      requiredFields: BASE_ATTESTATION_REQUIRED_FIELDS,
      requireTransparencyProof: false,
      enforceCertificatePolicy: false,
    };
  }

  if (isGeminiExtensionsManifest(filePath)) {
    return {
      id: "gemini",
      schemaProfile: "base",
      trustedIssuerDomains: [
        ...Array.from(TRUSTED_ATTESTATION_ISSUER_DOMAINS),
        "registry.npmjs.org",
        "npmjs.com",
      ],
      requiredFields: BASE_ATTESTATION_REQUIRED_FIELDS,
      requireTransparencyProof: false,
      enforceCertificatePolicy: false,
    };
  }

  if (isZedExtensionsManifest(filePath)) {
    return {
      id: "zed",
      schemaProfile: "strict",
      trustedIssuerDomains: [...Array.from(TRUSTED_ATTESTATION_ISSUER_DOMAINS), "zed.dev"],
      requiredFields: STRICT_ATTESTATION_REQUIRED_FIELDS,
      requireTransparencyProof: true,
      enforceCertificatePolicy: true,
    };
  }

  if (isRooMarketplaceManifest(filePath)) {
    return {
      id: "roo",
      schemaProfile: "strict",
      trustedIssuerDomains: [
        ...Array.from(TRUSTED_ATTESTATION_ISSUER_DOMAINS),
        "marketplace.roocode.com",
        "roocode.com",
      ],
      requiredFields: STRICT_ATTESTATION_REQUIRED_FIELDS,
      requireTransparencyProof: true,
      enforceCertificatePolicy: true,
    };
  }

  return {
    id: "default",
    schemaProfile: "base",
    trustedIssuerDomains: Array.from(TRUSTED_ATTESTATION_ISSUER_DOMAINS),
    requiredFields: BASE_ATTESTATION_REQUIRED_FIELDS,
    requireTransparencyProof: false,
    enforceCertificatePolicy: false,
  };
}

function incompleteAttestationRuleIdForProfile(profile: AttestationProfile): string {
  return profile.schemaProfile === "strict"
    ? "plugin-manifest-incomplete-attestation-strict"
    : "plugin-manifest-incomplete-attestation-base";
}

function hasPresentValue(value: unknown): boolean {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === "string") {
    return value.trim().length > 0;
  }
  if (typeof value === "boolean" || typeof value === "number") {
    return true;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (isRecord(value)) {
    return Object.keys(value).length > 0;
  }
  return true;
}

function issuerValueToHost(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }

  const parsed = parseSourceUrl(trimmed);
  if (parsed) {
    return parsed.hostname.toLowerCase();
  }

  if (/^[a-z0-9.-]+$/iu.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return null;
}

function collectAttestationIssuerHosts(value: unknown): string[] {
  const hosts = new Set<string>();

  function visit(candidate: unknown, issuerContext = false): void {
    if (typeof candidate === "string") {
      if (!issuerContext) {
        return;
      }
      const host = issuerValueToHost(candidate);
      if (host) {
        hosts.add(host);
      }
      return;
    }

    if (Array.isArray(candidate)) {
      for (const entry of candidate) {
        visit(entry, issuerContext);
      }
      return;
    }

    if (!isRecord(candidate)) {
      return;
    }

    for (const [key, child] of Object.entries(candidate)) {
      const normalizedKey = normalizeKey(key);
      const nextIssuerContext =
        issuerContext || normalizedKey.includes("issuer") || normalizedKey.includes("trustanchor");
      visit(child, nextIssuerContext);
    }
  }

  visit(value);
  return Array.from(hosts);
}

function attestationHasField(value: unknown, fieldKeys: Set<string>): boolean {
  if (Array.isArray(value)) {
    return value.some((entry) => attestationHasField(entry, fieldKeys));
  }
  if (!isRecord(value)) {
    return false;
  }

  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = normalizeKey(key);
    if (fieldKeys.has(normalizedKey) && hasPresentValue(child)) {
      return true;
    }
    if (attestationHasField(child, fieldKeys)) {
      return true;
    }
  }

  return false;
}

function isTrustedAttestationIssuer(
  host: string,
  profile: AttestationProfile,
  trustedApiDomains: string[],
): boolean {
  return [...trustedApiDomains, ...profile.trustedIssuerDomains].some((domain) =>
    matchesDomain(host, domain),
  );
}

function hasUnverifiedAttestationSignal(value: unknown): boolean {
  if (isExplicitlyUnverified(value)) {
    return true;
  }

  if (Array.isArray(value)) {
    return value.some((entry) => hasUnverifiedAttestationSignal(entry));
  }

  if (!isRecord(value)) {
    return false;
  }

  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = normalizeKey(key);
    if (
      normalizedKey.includes("verified") ||
      normalizedKey.includes("valid") ||
      normalizedKey.includes("trusted") ||
      normalizedKey.includes("status") ||
      normalizedKey.includes("result") ||
      normalizedKey.includes("state")
    ) {
      if (isExplicitlyUnverified(child)) {
        return true;
      }
    }

    if (hasUnverifiedAttestationSignal(child)) {
      return true;
    }
  }

  return false;
}

function hasFailureString(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.includes("invalid") ||
    normalized.includes("expired") ||
    normalized.includes("revoked") ||
    normalized.includes("failed") ||
    normalized.includes("failure") ||
    normalized.includes("error") ||
    normalized.includes("broken") ||
    normalized.includes("mismatch") ||
    normalized.includes("untrusted")
  );
}

function hasAttestationContextFailure(
  value: unknown,
  contextHints: Set<string>,
  inContext = false,
): boolean {
  if (Array.isArray(value)) {
    return value.some((entry) => hasAttestationContextFailure(entry, contextHints, inContext));
  }

  if (!isRecord(value)) {
    if (!inContext) {
      return false;
    }
    if (isExplicitlyUnverified(value)) {
      return true;
    }
    if (typeof value === "string" && hasFailureString(value)) {
      return true;
    }
    return false;
  }

  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = normalizeKey(key);
    const nextContext =
      inContext || Array.from(contextHints).some((hint) => normalizedKey.includes(hint));
    if (hasAttestationContextFailure(child, contextHints, nextContext)) {
      return true;
    }
  }
  return false;
}

function pathHasContextHint(path: string, contextHints: Set<string>): boolean {
  const normalizedPath = normalizeKey(path);
  for (const hint of contextHints) {
    if (normalizedPath.includes(hint)) {
      return true;
    }
  }
  return false;
}

function extractPolicyTokens(value: unknown): string[] {
  const tokens = new Set<string>();

  function addString(raw: string): void {
    const trimmed = raw.trim().toLowerCase();
    if (trimmed.length === 0) {
      return;
    }
    tokens.add(trimmed);
    tokens.add(normalizeKey(trimmed));

    const oidMatches = trimmed.match(/\b\d+(?:\.\d+){3,}\b/gu) ?? [];
    for (const oid of oidMatches) {
      tokens.add(oid);
      tokens.add(normalizeKey(oid));
    }

    for (const piece of trimmed.split(/[\s,;|/:_-]+/u)) {
      const normalizedPiece = normalizeKey(piece);
      if (normalizedPiece.length > 0) {
        tokens.add(normalizedPiece);
      }
    }
  }

  function visit(candidate: unknown): void {
    if (typeof candidate === "string") {
      addString(candidate);
      return;
    }
    if (typeof candidate === "number") {
      addString(String(candidate));
      return;
    }
    if (Array.isArray(candidate)) {
      for (const entry of candidate) {
        visit(entry);
      }
      return;
    }
    if (!isRecord(candidate)) {
      return;
    }
    for (const [key, child] of Object.entries(candidate)) {
      addString(key);
      visit(child);
    }
  }

  visit(value);
  return Array.from(tokens);
}

function assessCertificatePolicy(value: unknown): {
  hasPolicyMaterial: boolean;
  hasCodeSigningPolicy: boolean;
} {
  const nodes = walkRecord(value);
  const tokens = new Set<string>();

  for (const node of nodes) {
    const normalizedKey = normalizeKey(node.key);
    const isPolicyField = CERT_POLICY_FIELD_MARKERS.some((marker) =>
      normalizedKey.includes(marker),
    );
    if (!isPolicyField || !pathHasContextHint(node.path, ATTESTATION_CERT_CHAIN_CONTEXT_KEYS)) {
      continue;
    }
    for (const token of extractPolicyTokens(node.value)) {
      tokens.add(token);
    }
  }

  if (tokens.size === 0) {
    return { hasPolicyMaterial: false, hasCodeSigningPolicy: false };
  }

  const hasCodeSigningPolicy = Array.from(tokens).some((token) =>
    CODE_SIGNING_POLICY_TOKENS.has(token),
  );
  return {
    hasPolicyMaterial: true,
    hasCodeSigningPolicy,
  };
}

function parseNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^\d+$/u.test(trimmed)) {
      return Number.parseInt(trimmed, 10);
    }
  }
  return null;
}

function parseEpochSeconds(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value > 1_000_000_000_000) {
      return Math.floor(value / 1000);
    }
    if (value > 0) {
      return Math.floor(value);
    }
    return null;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length === 0) {
      return null;
    }
    const asNumber = parseNumber(trimmed);
    if (asNumber !== null) {
      return parseEpochSeconds(asNumber);
    }
    const parsedMillis = Date.parse(trimmed);
    if (!Number.isNaN(parsedMillis) && parsedMillis > 0) {
      return Math.floor(parsedMillis / 1000);
    }
  }

  return null;
}

function parseCheckpointTreeSize(value: string): number | null {
  const lines = value.split(/\r?\n/u);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (/^\d+$/u.test(line)) {
      return Number.parseInt(line, 10);
    }
  }
  return null;
}

function assessTransparencyCheckpointConsistency(value: unknown): {
  inconsistent: boolean;
  reasons: string[];
} {
  const nodes = walkRecord(value);
  const logIndexes: number[] = [];
  const treeSizes: number[] = [];
  const integratedTimes: number[] = [];

  for (const node of nodes) {
    const normalizedKey = normalizeKey(node.key);
    const inTransparencyContext =
      pathHasContextHint(node.path, ATTESTATION_TRANSPARENCY_CONTEXT_KEYS) ||
      Array.from(ATTESTATION_TRANSPARENCY_CONTEXT_KEYS).some((hint) =>
        normalizedKey.includes(hint),
      );
    if (!inTransparencyContext) {
      continue;
    }

    const isLogIndexKey = TRANSPARENCY_LOG_INDEX_KEY_MARKERS.some((marker) =>
      normalizedKey.includes(marker),
    );
    if (isLogIndexKey) {
      const parsed = parseNumber(node.value);
      if (parsed !== null) {
        logIndexes.push(parsed);
      }
    }

    const isTreeSizeKey = TRANSPARENCY_TREE_SIZE_KEY_MARKERS.some((marker) =>
      normalizedKey.includes(marker),
    );
    if (isTreeSizeKey) {
      const parsed = parseNumber(node.value);
      if (parsed !== null) {
        treeSizes.push(parsed);
      }
    }

    const isIntegratedTimeKey = TRANSPARENCY_INTEGRATED_TIME_KEY_MARKERS.some((marker) =>
      normalizedKey.includes(marker),
    );
    if (isIntegratedTimeKey) {
      const parsed = parseEpochSeconds(node.value);
      if (parsed !== null) {
        integratedTimes.push(parsed);
      }
    }

    if (normalizedKey.includes("checkpoint") && typeof node.value === "string") {
      const parsed = parseCheckpointTreeSize(node.value);
      if (parsed !== null) {
        treeSizes.push(parsed);
      }
    }
  }

  const reasons: string[] = [];
  if (logIndexes.length > 0 && treeSizes.length > 0) {
    const maxLogIndex = Math.max(...logIndexes);
    const maxTreeSize = Math.max(...treeSizes);
    if (maxLogIndex >= maxTreeSize) {
      reasons.push(`logIndex ${maxLogIndex} is not less than checkpoint treeSize ${maxTreeSize}`);
    }
  }

  if (integratedTimes.length > 0) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const maxIntegratedTime = Math.max(...integratedTimes);
    if (maxIntegratedTime > nowSeconds + TRANSPARENCY_FUTURE_SKEW_SECONDS) {
      reasons.push(`integratedTime ${maxIntegratedTime} is in the future`);
    }
  }

  return {
    inconsistent: reasons.length > 0,
    reasons,
  };
}

function releaseChannelTokens(value: unknown): string[] {
  const tokens = new Set<string>();

  function addToken(raw: string): void {
    const normalizedWhole = normalizeKey(raw);
    if (normalizedWhole.length > 0) {
      tokens.add(normalizedWhole);
    }
    for (const piece of raw.split(/[\s,;|/_-]+/u)) {
      const normalizedPiece = normalizeKey(piece);
      if (normalizedPiece.length > 0) {
        tokens.add(normalizedPiece);
      }
    }
  }

  function visit(candidate: unknown): void {
    if (typeof candidate === "string") {
      addToken(candidate);
      return;
    }
    if (Array.isArray(candidate)) {
      for (const entry of candidate) {
        visit(entry);
      }
      return;
    }
    if (!isRecord(candidate)) {
      return;
    }
    for (const child of Object.values(candidate)) {
      visit(child);
    }
  }

  visit(value);
  return Array.from(tokens);
}

function findUnstableReleaseChannelTokens(tokens: string[]): string[] {
  return tokens.filter((token) => UNSTABLE_RELEASE_CHANNEL_TOKENS.has(token));
}

function hasTransparencyProofMaterial(value: unknown): boolean {
  return attestationHasField(value, ATTESTATION_TRANSPARENCY_FIELD_KEYS);
}

function isManifestEntryPath(path: string): boolean {
  return /(^|\.)(plugins|extensions|marketplace)(\.|$)/iu.test(path);
}

function isAttestationPath(path: string): boolean {
  const normalized = normalizeKey(path);
  return (
    normalized.includes("attestation") ||
    normalized.includes("provenance") ||
    normalized.includes("slsa") ||
    normalized.includes("sigstore") ||
    normalized.includes("cosign")
  );
}

function hasPackageIdentityFields(parent: Record<string, unknown> | null): boolean {
  if (!parent) {
    return false;
  }
  for (const [key, value] of Object.entries(parent)) {
    if (PACKAGE_IDENTITY_KEYS.has(normalizeKey(key)) && hasPresentValue(value)) {
      return true;
    }
  }
  return false;
}

function hasSourceFields(parent: Record<string, unknown> | null): boolean {
  if (!parent) {
    return false;
  }
  for (const [key, value] of Object.entries(parent)) {
    if (SOURCE_KEYS.has(normalizeKey(key)) && hasPresentValue(value)) {
      return true;
    }
  }
  return false;
}

function parseVsCodeVersionQualifiedId(value: string): { baseId: string; version: string } | null {
  const trimmed = value.trim();
  const atIndex = trimmed.lastIndexOf("@");
  if (atIndex <= 0 || atIndex === trimmed.length - 1) {
    return null;
  }
  const baseId = trimmed.slice(0, atIndex).trim();
  const version = trimmed.slice(atIndex + 1).trim();
  if (!isScopedVsCodeExtensionId(baseId) || version.length === 0) {
    return null;
  }
  return { baseId, version };
}

function namespaceFromScopedExtensionId(value: string): string | null {
  const trimmed = value.trim();
  if (!isScopedVsCodeExtensionId(trimmed)) {
    return null;
  }
  return trimmed.split(".")[0]?.toLowerCase() ?? null;
}

function isUnpinnedVersionSelector(value: string): boolean {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.length === 0) {
    return false;
  }

  if (UNPINNED_VERSION_TOKENS.has(trimmed)) {
    return true;
  }

  if (
    trimmed.startsWith("^") ||
    trimmed.startsWith("~") ||
    trimmed.startsWith(">") ||
    trimmed.startsWith("<") ||
    trimmed.includes("*") ||
    trimmed.includes("||") ||
    trimmed.includes(" - ")
  ) {
    return true;
  }

  if (/(^|[.-])x($|[.-])/iu.test(trimmed)) {
    return true;
  }

  if (/(alpha|beta|rc|preview|canary|nightly|insider|dev|next|edge)/iu.test(trimmed)) {
    return true;
  }

  return false;
}

function hasIntegrityMetadata(parent: Record<string, unknown> | null): boolean {
  if (!parent) {
    return false;
  }

  for (const [key, value] of Object.entries(parent)) {
    if (!INTEGRITY_KEYS.has(normalizeKey(key))) {
      continue;
    }

    if (typeof value === "string") {
      return value.trim().length > 0;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return true;
    }
    if (Array.isArray(value)) {
      return value.length > 0;
    }
    if (isRecord(value)) {
      return Object.values(value).some(
        (entry) => entry !== null && entry !== undefined && `${entry}`.length > 0,
      );
    }
  }

  return false;
}

function hasAttestationMetadata(parent: Record<string, unknown> | null): boolean {
  if (!parent) {
    return false;
  }

  for (const [key, value] of Object.entries(parent)) {
    if (!ATTESTATION_KEYS.has(normalizeKey(key))) {
      continue;
    }
    if (hasPresentValue(value)) {
      return true;
    }
  }

  return false;
}

function extractCommandString(value: unknown): string | null {
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }

  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) {
    return (value as string[]).join(" ").trim();
  }

  if (isRecord(value)) {
    if (typeof value.command === "string" && value.command.trim().length > 0) {
      return value.command.trim();
    }
    if (Array.isArray(value.command) && value.command.every((entry) => typeof entry === "string")) {
      return (value.command as string[]).join(" ").trim();
    }
  }

  return null;
}

function tokenizeCommand(command: string): string[] {
  return command
    .split(/\s+/u)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
}

function hasSuspiciousInstallCommand(command: string, blockedCommands: string[]): boolean {
  const tokens = tokenizeCommand(command);
  const hasBlockedBinary = tokens.some((token) => blockedCommands.includes(token));
  return (
    hasBlockedBinary || SHELL_META_PATTERN.test(command) || NETWORK_UTILITY_PATTERN.test(command)
  );
}

function isUserScopeManifest(filePath: string): boolean {
  return filePath.startsWith("~/");
}

function downgradeSeverity(severity: Finding["severity"]): Finding["severity"] {
  const index = SEVERITY_ORDER.indexOf(severity);
  if (index < 0) {
    return severity;
  }
  return SEVERITY_ORDER[Math.min(index + 1, SEVERITY_ORDER.length - 1)] ?? severity;
}

function resolveSeverity(
  filePath: string,
  ruleId: string,
  severity: Finding["severity"],
): Finding["severity"] {
  if (!isUserScopeManifest(filePath)) {
    return severity;
  }
  if (!USER_SCOPE_ADVISORY_RULE_IDS.has(ruleId)) {
    return severity;
  }
  return downgradeSeverity(severity);
}

function makeFinding(
  input: PluginManifestInput,
  field: string,
  ruleId: string,
  severity: Finding["severity"],
  description: string,
  evidence?: FindingEvidence | null,
): Finding {
  const location: Finding["location"] = { field };
  if (typeof evidence?.line === "number") {
    location.line = evidence.line;
  }
  if (typeof evidence?.column === "number") {
    location.column = evidence.column;
  }
  const resolvedSeverity = resolveSeverity(input.filePath, ruleId, severity);

  return {
    rule_id: ruleId,
    finding_id: `PLUGIN_MANIFEST-${input.filePath}-${field}-${ruleId}`,
    severity: resolvedSeverity,
    category: "COMMAND_EXEC",
    layer: "L2",
    file_path: input.filePath,
    location,
    description,
    affected_tools: [
      "claude-code",
      "codex-cli",
      "opencode",
      "cursor",
      "windsurf",
      "github-copilot",
      "gemini-cli",
      "roo-code",
      "cline",
      "zed",
      "jetbrains-junie",
    ],
    cve: null,
    owasp: ["ASI02", "ASI04"],
    cwe: "CWE-829",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field", "replace_with_default"],
    evidence: evidence?.evidence ?? null,
    suppressed: false,
  };
}

interface TraversalNode {
  path: string;
  key: string;
  value: unknown;
  parent: Record<string, unknown> | null;
}

function walkRecord(
  value: unknown,
  path = "",
  parent: Record<string, unknown> | null = null,
): TraversalNode[] {
  const nodes: TraversalNode[] = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      const childPath = path.length > 0 ? `${path}.${index}` : `${index}`;
      nodes.push(...walkRecord(entry, childPath, parent));
    });
    return nodes;
  }
  if (!isRecord(value)) {
    return nodes;
  }

  for (const [key, child] of Object.entries(value)) {
    const childPath = path.length > 0 ? `${path}.${key}` : key;
    nodes.push({ path: childPath, key, value: child, parent: value });
    nodes.push(...walkRecord(child, childPath, value));
  }
  return nodes;
}

export function detectPluginManifestIssues(input: PluginManifestInput): Finding[] {
  if (!shouldInspectFile(input.filePath) || !isRecord(input.parsed)) {
    return [];
  }

  const findings: Finding[] = [];
  const nodes = walkRecord(input.parsed);
  const kiroRegistryHostObservations: Array<{ path: string; host: string }> = [];

  for (const node of nodes) {
    const normalizedKey = normalizeKey(node.key);

    if (
      PACKAGE_IDENTITY_KEYS.has(normalizedKey) &&
      typeof node.value === "string" &&
      isMarketplaceSemanticsManifest(input.filePath) &&
      isManifestEntryPath(node.path)
    ) {
      if (isInvalidPackageIdentity(node.value)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [node.value],
          fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-invalid-package-identity",
            "HIGH",
            `Plugin identity field contains invalid path/URL-like value: ${node.value}`,
            evidence,
          ),
        );
      } else if (isDisallowedNamespace(node.value, input.filePath)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [node.value],
          fallbackValue: `${node.path} uses disallowed namespace token`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-disallowed-namespace",
            "MEDIUM",
            `Plugin identity uses disallowed publisher/namespace token: ${node.value}`,
            evidence,
          ),
        );
      }
    }

    if (SOURCE_KEYS.has(normalizedKey) && typeof node.value === "string") {
      if (
        isMarketplaceSemanticsManifest(input.filePath) &&
        isManifestEntryPath(node.path) &&
        !hasPackageIdentityFields(node.parent)
      ) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [node.value],
          fallbackValue: `${node.path} has source metadata but no package identity fields`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-missing-package-identity",
            "MEDIUM",
            "Plugin entry includes source metadata but lacks package identity fields (id/name/package)",
            evidence,
          ),
        );
      }

      if (isLocalSourcePath(node.value)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [node.value],
          fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-local-source-path",
            "HIGH",
            `Plugin source points to local path: ${node.value}`,
            evidence,
          ),
        );
      }

      const parsed = parseSourceUrl(node.value);

      if (
        IMAGE_KEYS.has(normalizedKey) &&
        isImageReference(node.value) &&
        !isDigestPinnedImage(node.value)
      ) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [node.value],
          fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-unpinned-image",
            "MEDIUM",
            `Container image is not digest-pinned: ${node.value}`,
            evidence,
          ),
        );
      }

      if (isLikelyGitSource(node.value, parsed) && !hasPinnedGitCommit(node.value, parsed)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [node.value],
          fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-unpinned-git-source",
            "MEDIUM",
            `Git-based plugin source is not pinned to a commit hash: ${node.value}`,
            evidence,
          ),
        );
      }

      if (parsed) {
        if (
          parsed.protocol === "https:" &&
          isArtifactSourceUrl(parsed) &&
          !hasIntegrityMetadata(node.parent)
        ) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            searchTerms: [node.value],
            fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-missing-integrity",
              "MEDIUM",
              `Direct plugin artifact source is missing integrity metadata: ${node.value}`,
              evidence,
            ),
          );
        }

        if (parsed.protocol === "http:") {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            searchTerms: [node.value],
            fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-insecure-source-url",
              "HIGH",
              `Plugin source uses insecure HTTP URL: ${node.value}`,
              evidence,
            ),
          );
          continue;
        }

        if (
          isKiroExtensionRegistryField(input.filePath, normalizedKey, node.path) &&
          parsed.protocol === "https:"
        ) {
          kiroRegistryHostObservations.push({
            path: node.path,
            host: parsed.hostname.toLowerCase(),
          });
          if (!isTrustedKiroExtensionRegistryDomain(parsed.hostname, input.trustedApiDomains)) {
            const evidence = buildFindingEvidence({
              textContent: input.textContent,
              jsonPaths: [node.path],
              searchTerms: [node.value],
              fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
            });
            findings.push(
              makeFinding(
                input,
                node.path,
                "plugin-manifest-nonallowlisted-extension-registry",
                "MEDIUM",
                `Kiro extension registry endpoint is not allowlisted: ${parsed.hostname}`,
                evidence,
              ),
            );
          }
          continue;
        }

        if (
          parsed.protocol === "https:" &&
          !isTrustedSourceDomain(parsed.hostname, input.trustedApiDomains)
        ) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            searchTerms: [node.value],
            fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-untrusted-source-url",
              "MEDIUM",
              `Plugin source points to untrusted domain: ${parsed.hostname}`,
              evidence,
            ),
          );
        }

        const marketplacePolicy = marketplaceSourcePolicyForFile(input.filePath);
        if (
          parsed.protocol === "https:" &&
          marketplacePolicy &&
          requiresMarketplaceProvenance(marketplacePolicy) &&
          isAllowedByMarketplacePolicy(parsed.hostname, marketplacePolicy) &&
          !isArtifactSourceUrl(parsed) &&
          !hasIntegrityMetadata(node.parent) &&
          !hasAttestationMetadata(node.parent)
        ) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            searchTerms: [node.value],
            fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-missing-marketplace-provenance",
              "MEDIUM",
              `Marketplace plugin source on ${parsed.hostname} is missing provenance metadata (integrity digest or attestation)`,
              evidence,
            ),
          );
        }

        if (
          parsed.protocol === "https:" &&
          marketplacePolicy &&
          isMarketplaceAnchorDomain(parsed.hostname) &&
          !isAllowedByMarketplacePolicy(parsed.hostname, marketplacePolicy) &&
          !isUserTrustedDomain(parsed.hostname, input.trustedApiDomains)
        ) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            searchTerms: [node.value],
            fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-cross-marketplace-source",
              "MEDIUM",
              `Plugin source domain ${parsed.hostname} is outside ${marketplacePolicy.id} marketplace policy`,
              evidence,
            ),
          );
        }
      }
    }

    if (
      VERSION_FIELD_KEYS.has(normalizedKey) &&
      typeof node.value === "string" &&
      isMarketplaceSemanticsManifest(input.filePath) &&
      !isAttestationPath(node.path) &&
      (isManifestEntryPath(node.path) ||
        hasPackageIdentityFields(node.parent) ||
        hasSourceFields(node.parent))
    ) {
      if (isUnpinnedVersionSelector(node.value)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [node.value],
          fallbackValue: `${node.path} = ${JSON.stringify(node.value)}`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-unpinned-version",
            "MEDIUM",
            `Plugin entry uses unpinned or unstable version selector: ${node.value}`,
            evidence,
          ),
        );
      }
    }

    if (INSTALL_SCRIPT_KEYS.has(normalizedKey)) {
      const command = extractCommandString(node.value);
      if (!command || !hasSuspiciousInstallCommand(command, input.blockedCommands)) {
        continue;
      }
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: [node.path],
        searchTerms: [command],
        fallbackValue: `${node.path} = ${JSON.stringify(command)}`,
      });
      findings.push(
        makeFinding(
          input,
          node.path,
          "plugin-manifest-install-script",
          "CRITICAL",
          `Suspicious plugin install script detected: ${command}`,
          evidence,
        ),
      );
    }

    if (PERMISSION_KEYS.has(normalizedKey)) {
      const tokens = collectPermissionTokens(node.value);
      const wildcardTokens = Array.from(new Set(findWildcardPermissionTokens(tokens)));
      if (wildcardTokens.length > 0) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: wildcardTokens,
          fallbackValue: `${node.path} contains wildcard permission grants`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-wildcard-permissions",
            "HIGH",
            `Plugin permissions include wildcard grants: ${wildcardTokens.join(", ")}`,
            evidence,
          ),
        );
        continue;
      }

      const riskyTokens = Array.from(new Set(findRiskyCapabilityTokens(tokens)));
      if (riskyTokens.length > 0) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: riskyTokens,
          fallbackValue: `${node.path} contains risky capability grants`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-risky-capabilities",
            "MEDIUM",
            `Plugin permissions include risky capability grants: ${riskyTokens.join(", ")}`,
            evidence,
          ),
        );
      }
    }

    if (UNVERIFIED_PUBLISHER_KEYS.has(normalizedKey) && isExplicitlyUnverified(node.value)) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: [node.path],
        fallbackValue: `${node.path} is marked unverified`,
      });
      findings.push(
        makeFinding(
          input,
          node.path,
          "plugin-manifest-unverified-publisher",
          "HIGH",
          "Plugin publisher/signature metadata is explicitly marked unverified",
          evidence,
        ),
      );
    }

    if (SIGNATURE_BYPASS_KEYS.has(normalizedKey) && isAffirmative(node.value)) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: [node.path],
        fallbackValue: `${node.path} enables verification bypass`,
      });
      findings.push(
        makeFinding(
          input,
          node.path,
          "plugin-manifest-signature-bypass",
          "HIGH",
          "Plugin manifest enables signature/checksum verification bypass",
          evidence,
        ),
      );
    }

    if (
      isKiroProductManifest(input.filePath) &&
      normalizeKey(node.path).includes("extensionsgallery") &&
      ((PUBLISHER_TRUST_BYPASS_KEYS.has(normalizedKey) && isAffirmative(node.value)) ||
        (PUBLISHER_TRUST_DISABLED_KEYS.has(normalizedKey) && isExplicitlyUnverified(node.value)))
    ) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: [node.path],
        fallbackValue: `${node.path} weakens extension publisher trust verification`,
      });
      findings.push(
        makeFinding(
          input,
          node.path,
          "plugin-manifest-publisher-trust-bypass",
          "HIGH",
          "Kiro extension publisher trust-policy verification is bypassed or disabled",
          evidence,
        ),
      );
    }

    if (TRANSPARENCY_BYPASS_KEYS.has(normalizedKey) && isAffirmative(node.value)) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: [node.path],
        fallbackValue: `${node.path} bypasses transparency proof verification`,
      });
      findings.push(
        makeFinding(
          input,
          node.path,
          "plugin-manifest-transparency-bypass",
          "HIGH",
          "Plugin manifest disables or bypasses transparency-log proof verification",
          evidence,
        ),
      );
    }

    if (ATTESTATION_KEYS.has(normalizedKey)) {
      const profile = attestationProfileForFile(input.filePath);
      if (hasUnverifiedAttestationSignal(node.value)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          fallbackValue: `${node.path} attestation/provenance metadata is unverified`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-unverified-attestation",
            "HIGH",
            "Plugin attestation/provenance metadata indicates verification failure or unverified state",
            evidence,
          ),
        );
      }

      const issuerHosts = collectAttestationIssuerHosts(node.value);
      const untrustedIssuerHosts = issuerHosts.filter(
        (host) => !isTrustedAttestationIssuer(host, profile, input.trustedApiDomains),
      );
      if (untrustedIssuerHosts.length > 0) {
        const uniqueHosts = Array.from(new Set(untrustedIssuerHosts));
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: uniqueHosts,
          fallbackValue: `${node.path} contains untrusted attestation issuers`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-untrusted-attestation-issuer",
            "MEDIUM",
            `Attestation issuer is not trusted: ${uniqueHosts.join(", ")}`,
            evidence,
          ),
        );
      }

      const missingParts = profile.requiredFields
        .filter((requirement) => !attestationHasField(node.value, requirement.keys))
        .map((requirement) => requirement.label);
      if (missingParts.length > 0) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          fallbackValue: `${node.path} is missing attestation fields: ${missingParts.join(", ")}`,
        });
        const profileRuleId = incompleteAttestationRuleIdForProfile(profile);
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-incomplete-attestation",
            "MEDIUM",
            `Attestation metadata is incomplete (missing: ${missingParts.join(", ")})`,
            evidence,
          ),
        );
        findings.push(
          makeFinding(
            input,
            node.path,
            profileRuleId,
            "MEDIUM",
            `Attestation metadata is incomplete for ${profile.schemaProfile} profile (missing: ${missingParts.join(", ")})`,
            evidence,
          ),
        );
      }

      if (profile.enforceCertificatePolicy) {
        const certPolicy = assessCertificatePolicy(node.value);
        if (certPolicy.hasPolicyMaterial && !certPolicy.hasCodeSigningPolicy) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            fallbackValue: `${node.path} contains certificate policy fields without code-signing EKU/OID`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-invalid-cert-policy",
              "HIGH",
              "Attestation certificate policy lacks code-signing EKU/OID constraints",
              evidence,
            ),
          );
        }
      }

      if (hasAttestationContextFailure(node.value, ATTESTATION_CERT_CHAIN_CONTEXT_KEYS)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          fallbackValue: `${node.path} contains certificate-chain verification failures`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-invalid-cert-chain",
            "HIGH",
            "Attestation metadata indicates certificate-chain verification failure",
            evidence,
          ),
        );
      }

      if (hasAttestationContextFailure(node.value, ATTESTATION_TRANSPARENCY_CONTEXT_KEYS)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          fallbackValue: `${node.path} contains transparency-log proof verification failures`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-transparency-proof-failed",
            "HIGH",
            "Attestation metadata indicates transparency-log proof verification failure",
            evidence,
          ),
        );
      }

      const transparencyCheckpointAssessment = assessTransparencyCheckpointConsistency(node.value);
      if (transparencyCheckpointAssessment.inconsistent) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          fallbackValue: `${node.path} has inconsistent transparency checkpoint metadata`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-transparency-checkpoint-inconsistent",
            "HIGH",
            `Transparency checkpoint metadata is inconsistent (${transparencyCheckpointAssessment.reasons.join("; ")})`,
            evidence,
          ),
        );
      }

      if (profile.requireTransparencyProof && !hasTransparencyProofMaterial(node.value)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          fallbackValue: `${node.path} is missing transparency-log proof metadata`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-missing-transparency-proof",
            "MEDIUM",
            "Attestation metadata is missing required transparency-log proof fields for this profile",
            evidence,
          ),
        );
      }
    }

    if (PRERELEASE_FLAG_KEYS.has(normalizedKey) && isAffirmative(node.value)) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: [node.path],
        fallbackValue: `${node.path} enables prerelease/preview channel usage`,
      });
      findings.push(
        makeFinding(
          input,
          node.path,
          "plugin-manifest-unstable-release-channel",
          "MEDIUM",
          "Plugin manifest opts into prerelease or preview release channels",
          evidence,
        ),
      );
    }

    if (RELEASE_CHANNEL_KEYS.has(normalizedKey)) {
      const unstableTokens = Array.from(
        new Set(findUnstableReleaseChannelTokens(releaseChannelTokens(node.value))),
      );
      if (unstableTokens.length > 0) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: unstableTokens,
          fallbackValue: `${node.path} targets unstable release channels`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-unstable-release-channel",
            "MEDIUM",
            `Plugin manifest targets unstable release channels: ${unstableTokens.join(", ")}`,
            evidence,
          ),
        );
      }
    }

    if (
      isZedExtensionsManifest(input.filePath) &&
      normalizedKey === "id" &&
      typeof node.value === "string" &&
      isManifestEntryPath(node.path)
    ) {
      const trimmed = node.value.trim();
      if (!isScopedVsCodeExtensionId(trimmed)) {
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [trimmed],
          fallbackValue: `${node.path} contains unscoped extension id ${trimmed}`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-unscoped-extension-id",
            "MEDIUM",
            `Zed extension id is not publisher-scoped: ${trimmed}`,
            evidence,
          ),
        );
      } else if (
        node.parent &&
        typeof node.parent.publisher === "string" &&
        node.parent.publisher.trim().length > 0
      ) {
        const idNamespace = namespaceFromScopedExtensionId(trimmed);
        const publisherNamespace = node.parent.publisher.trim().toLowerCase();
        if (idNamespace && idNamespace !== publisherNamespace) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            searchTerms: [trimmed, node.parent.publisher],
            fallbackValue: `${node.path} namespace ${idNamespace} does not match publisher ${publisherNamespace}`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-publisher-identity-mismatch",
              "HIGH",
              `Zed extension id namespace ${idNamespace} does not match declared publisher ${publisherNamespace}`,
              evidence,
            ),
          );
        }
      }
    }

    if (
      isVsCodeExtensionsManifest(input.filePath) &&
      VSCODE_RECOMMENDATION_KEYS.has(normalizedKey)
    ) {
      if (!Array.isArray(node.value)) {
        continue;
      }
      for (const entry of node.value) {
        if (typeof entry !== "string") {
          continue;
        }
        const trimmed = entry.trim();
        if (trimmed.length === 0) {
          continue;
        }

        const versionQualified = parseVsCodeVersionQualifiedId(trimmed);
        if (versionQualified) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            searchTerms: [trimmed],
            fallbackValue: `${node.path} contains version-qualified extension id ${trimmed}`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-versioned-extension-id",
              "MEDIUM",
              `VS Code extension recommendation includes version selector; use plain publisher-scoped id only: ${trimmed}`,
              evidence,
            ),
          );
          continue;
        }

        if (isInvalidVsCodeRecommendationEntry(trimmed)) {
          const evidence = buildFindingEvidence({
            textContent: input.textContent,
            jsonPaths: [node.path],
            searchTerms: [trimmed],
            fallbackValue: `${node.path} contains invalid extension recommendation entry ${trimmed}`,
          });
          findings.push(
            makeFinding(
              input,
              node.path,
              "plugin-manifest-invalid-extension-id",
              "HIGH",
              `VS Code extension recommendation contains invalid path/URL-like entry: ${trimmed}`,
              evidence,
            ),
          );
          continue;
        }

        if (isScopedVsCodeExtensionId(trimmed)) {
          if (isDisallowedNamespace(trimmed, input.filePath)) {
            const evidence = buildFindingEvidence({
              textContent: input.textContent,
              jsonPaths: [node.path],
              searchTerms: [trimmed],
              fallbackValue: `${node.path} contains disallowed namespace id ${trimmed}`,
            });
            findings.push(
              makeFinding(
                input,
                node.path,
                "plugin-manifest-disallowed-namespace",
                "MEDIUM",
                `VS Code extension recommendation uses disallowed publisher namespace: ${trimmed}`,
                evidence,
              ),
            );
          }
          continue;
        }
        const evidence = buildFindingEvidence({
          textContent: input.textContent,
          jsonPaths: [node.path],
          searchTerms: [trimmed],
          fallbackValue: `${node.path} contains unscoped extension id ${trimmed}`,
        });
        findings.push(
          makeFinding(
            input,
            node.path,
            "plugin-manifest-unscoped-extension-id",
            "MEDIUM",
            `VS Code extension recommendation is not publisher-scoped: ${trimmed}`,
            evidence,
          ),
        );
      }
    }
  }

  if (isKiroProductManifest(input.filePath)) {
    const uniqueHosts = Array.from(
      new Set(kiroRegistryHostObservations.map((entry) => entry.host)),
    );
    if (uniqueHosts.length > 1) {
      const evidence = buildFindingEvidence({
        textContent: input.textContent,
        jsonPaths: kiroRegistryHostObservations.map((entry) => entry.path),
        searchTerms: uniqueHosts,
        fallbackValue: `extensionsGallery uses multiple registry hosts: ${uniqueHosts.join(", ")}`,
      });
      findings.push(
        makeFinding(
          input,
          "extensionsGallery",
          "plugin-manifest-extension-registry-host-mismatch",
          "MEDIUM",
          `Kiro extensionsGallery endpoints reference multiple hosts: ${uniqueHosts.join(", ")}`,
          evidence,
        ),
      );
    }
  }

  return findings;
}
