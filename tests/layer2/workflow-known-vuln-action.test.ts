import { describe, expect, it } from "vitest";
import { runStaticEngine, type StaticEngineConfig } from "../../src/layer2-static/engine";

const BASE_CONFIG: StaticEngineConfig = {
  knownSafeMcpServers: [],
  knownSafeFormatters: [],
  knownSafeLspServers: [],
  knownSafeHooks: [],
  blockedCommands: ["bash", "sh"],
  trustedApiDomains: [],
  unicodeAnalysis: true,
  checkIdeSettings: true,
  persona: "regular",
  runtimeMode: "offline",
  workflowAuditsEnabled: true,
};

describe("workflow known vulnerable action detector", () => {
  it("runs only in online mode", async () => {
    const commonInput = {
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/ci.yml",
          format: "yaml" as const,
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              test: {
                steps: [{ uses: "actions/checkout@v3" }],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
    };

    const offline = await runStaticEngine({
      ...commonInput,
      config: {
        ...BASE_CONFIG,
        runtimeMode: "offline",
      },
    });

    const online = await runStaticEngine({
      ...commonInput,
      config: {
        ...BASE_CONFIG,
        runtimeMode: "online",
      },
    });

    expect(offline.some((finding) => finding.rule_id === "workflow-known-vuln-action")).toBe(false);
    expect(online.some((finding) => finding.rule_id === "workflow-known-vuln-action")).toBe(true);
  });

  it("flags known vulnerable refs when used as reusable workflow at job level", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/release.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["workflow_dispatch"],
            jobs: {
              release: {
                uses: "actions/checkout@v3",
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: {
        ...BASE_CONFIG,
        runtimeMode: "online",
      },
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-known-vuln-action")).toBe(true);
    expect(findings.some((finding) => finding.location.field === "jobs.release.uses")).toBe(true);
  });

  it("flags refs matching vulnerable semver ranges from the advisory bundle", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/security.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              scan: {
                steps: [{ uses: "aquasecurity/trivy-action@0.34.9" }],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: {
        ...BASE_CONFIG,
        runtimeMode: "online",
      },
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-known-vuln-action")).toBe(true);
  });

  it("does not flag refs outside vulnerable semver ranges from the advisory bundle", async () => {
    const findings = await runStaticEngine({
      projectRoot: "/tmp/project",
      files: [
        {
          filePath: ".github/workflows/security.yml",
          format: "yaml",
          textContent: "",
          parsed: {
            on: ["push"],
            jobs: {
              scan: {
                steps: [{ uses: "aquasecurity/trivy-action@0.35.0" }],
              },
            },
          },
        },
      ],
      symlinkEscapes: [],
      hooks: [],
      config: {
        ...BASE_CONFIG,
        runtimeMode: "online",
      },
    });

    expect(findings.some((finding) => finding.rule_id === "workflow-known-vuln-action")).toBe(
      false,
    );
  });
});
