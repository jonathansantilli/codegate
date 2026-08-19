import { describe, expect, it } from "vitest";
import {
  detectMcpPackageHygiene,
  findLikelyTyposquatTarget,
  isPinnedLocator,
  PACKAGE_REGISTRY,
} from "../../src/layer2-static/detectors/mcp-package-hygiene";

function input(parsed: unknown, knownSafe: string[] = []) {
  return { filePath: ".mcp.json", parsed, knownSafeMcpServers: knownSafe };
}

describe("package pinning", () => {
  it("treats exact versions as pinned", () => {
    expect(isPinnedLocator(PACKAGE_REGISTRY.Npm, "some-pkg@1.2.3")).toBe(true);
    expect(isPinnedLocator(PACKAGE_REGISTRY.Npm, "@scope/pkg@0.4.1-beta.2")).toBe(true);
    expect(isPinnedLocator(PACKAGE_REGISTRY.Pypi, "some-pkg==1.2.3")).toBe(true);
  });

  it("treats bare names, tags, and ranges as unpinned", () => {
    expect(isPinnedLocator(PACKAGE_REGISTRY.Npm, "some-pkg")).toBe(false);
    expect(isPinnedLocator(PACKAGE_REGISTRY.Npm, "some-pkg@latest")).toBe(false);
    expect(isPinnedLocator(PACKAGE_REGISTRY.Npm, "some-pkg@^1.2.3")).toBe(false);
    expect(isPinnedLocator(PACKAGE_REGISTRY.Pypi, "some-pkg>=1.0")).toBe(false);
    expect(isPinnedLocator(PACKAGE_REGISTRY.Pypi, "some-pkg")).toBe(false);
  });
});

describe("typosquat matching", () => {
  it("matches one-edit variants of popular packages", () => {
    expect(findLikelyTyposquatTarget(PACKAGE_REGISTRY.Npm, "firecrawl-mpc")).toBe("firecrawl-mcp");
    expect(
      findLikelyTyposquatTarget(PACKAGE_REGISTRY.Npm, "@modelcontextprotocol/server-guthub"),
    ).toBe("@modelcontextprotocol/server-github");
  });

  it("does not flag exact popular names or distant names", () => {
    expect(findLikelyTyposquatTarget(PACKAGE_REGISTRY.Npm, "firecrawl-mcp")).toBeNull();
    expect(findLikelyTyposquatTarget(PACKAGE_REGISTRY.Npm, "totally-unrelated-package")).toBeNull();
  });
});

describe("mcp package hygiene detector", () => {
  it("flags unpinned npx launches, noting auto-confirm", () => {
    const findings = detectMcpPackageHygiene(
      input({
        mcpServers: {
          helper: { command: "npx", args: ["-y", "some-helper-pkg"] },
        },
      }),
    );
    const unpinned = findings.find((finding) => finding.rule_id === "mcp-unpinned-package");
    expect(unpinned?.severity).toBe("MEDIUM");
    expect(unpinned?.description).toContain("auto-confirms");
    expect(unpinned?.location.field).toBe("mcpServers.helper");
  });

  it("supports command arrays and uvx launches", () => {
    const findings = detectMcpPackageHygiene(
      input({
        mcp_servers: {
          pytool: { command: ["uvx", "some-python-tool"] },
        },
      }),
    );
    expect(findings.map((finding) => finding.rule_id)).toContain("mcp-unpinned-package");
  });

  it("flags likely typosquats as HIGH", () => {
    const findings = detectMcpPackageHygiene(
      input({
        mcpServers: {
          crawler: { command: "npx", args: ["firecrawl-mpc@1.0.0"] },
        },
      }),
    );
    const typosquat = findings.find((finding) => finding.rule_id === "mcp-possible-typosquat");
    expect(typosquat?.severity).toBe("HIGH");
    expect(typosquat?.description).toContain("firecrawl-mcp");
  });

  it("skips known-safe servers and pinned popular packages", () => {
    const findings = detectMcpPackageHygiene(
      input(
        {
          mcpServers: {
            github: { command: "npx", args: ["@modelcontextprotocol/server-github"] },
            pinned: { command: "npx", args: ["firecrawl-mcp@1.2.3"] },
          },
        },
        ["@modelcontextprotocol/server-github"],
      ),
    );
    expect(findings).toHaveLength(0);
  });

  it("finds servers nested deeper in the config", () => {
    const findings = detectMcpPackageHygiene(
      input({
        profiles: {
          default: {
            mcpServers: { helper: { command: "npx", args: ["some-helper"] } },
          },
        },
      }),
    );
    expect(findings.map((finding) => finding.rule_id)).toContain("mcp-unpinned-package");
    expect(findings[0]?.location.field).toBe("profiles.default.mcpServers.helper");
  });
});
