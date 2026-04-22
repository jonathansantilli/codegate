import { describe, expect, it } from "vitest";
import { buildResourceId, normalizeRemoteUrl } from "../../src/layer3-dynamic/url-validation";

describe("normalizeRemoteUrl", () => {
  it("accepts http and https URLs and returns them in canonical form", () => {
    const http = normalizeRemoteUrl("http://0.0.0.0:8007/mcp");
    expect(http.ok).toBe(true);
    if (http.ok) {
      expect(http.url).toBe("http://0.0.0.0:8007/mcp");
      expect(http.scheme).toBe("http");
    }

    const https = normalizeRemoteUrl("https://mcp.linear.app/mcp");
    expect(https.ok).toBe(true);
    if (https.ok) {
      expect(https.url).toBe("https://mcp.linear.app/mcp");
      expect(https.scheme).toBe("https");
    }
  });

  it("rejects non http/https schemes", () => {
    expect(normalizeRemoteUrl("file:///etc/passwd").ok).toBe(false);
    expect(normalizeRemoteUrl("ftp://ftp.example.com/pub").ok).toBe(false);
    expect(normalizeRemoteUrl("ssh://user@example.com").ok).toBe(false);
    const result = normalizeRemoteUrl("javascript:alert(1)");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("missing_scheme");
    }
  });

  it("rejects URLs without a host", () => {
    const bare = normalizeRemoteUrl("http://");
    expect(bare.ok).toBe(false);
    const justScheme = normalizeRemoteUrl("http:");
    expect(justScheme.ok).toBe(false);
    if (!justScheme.ok) {
      expect(justScheme.reason).toBe("missing_host");
    }
  });

  it("rejects empty / whitespace input", () => {
    expect(normalizeRemoteUrl("").ok).toBe(false);
    expect(normalizeRemoteUrl("   ").ok).toBe(false);
  });

  it("strips trailing slashes from non-root paths and preserves root slash", () => {
    const withSlash = normalizeRemoteUrl("https://example.com/api/v1/");
    expect(withSlash.ok).toBe(true);
    if (withSlash.ok) {
      expect(withSlash.url).toBe("https://example.com/api/v1");
    }

    // Root path: URL class already canonicalises to trailing `/` which we keep.
    const root = normalizeRemoteUrl("https://example.com");
    expect(root.ok).toBe(true);
    if (root.ok) {
      expect(root.url).toBe("https://example.com/");
    }
  });
});

describe("buildResourceId", () => {
  it("uses the URL itself (no double scheme) for http and sse kinds", () => {
    expect(buildResourceId("http", "https://mcp.linear.app/mcp")).toBe(
      "https://mcp.linear.app/mcp",
    );
    expect(buildResourceId("http", "http://0.0.0.0:8007/mcp")).toBe("http://0.0.0.0:8007/mcp");
    expect(buildResourceId("sse", "https://example.com/sse")).toBe("https://example.com/sse");
  });

  it("preserves the kind prefix for registry metadata kinds", () => {
    expect(buildResourceId("npm", "@org/pkg")).toBe("npm:@org/pkg");
    expect(buildResourceId("pypi", "requests")).toBe("pypi:requests");
    expect(buildResourceId("git", "https://github.com/org/repo")).toBe(
      "git:https://github.com/org/repo",
    );
  });

  it("produces resource IDs that do not start with http:http or http:https", () => {
    for (const url of [
      "http://0.0.0.0:8007/mcp",
      "https://mcp.linear.app/mcp",
      "https://example.com/sse",
    ]) {
      const id = buildResourceId("http", url);
      expect(id.startsWith("http:http://")).toBe(false);
      expect(id.startsWith("http:https://")).toBe(false);
    }
  });
});
