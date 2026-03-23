import { describe, expect, it } from "vitest";
import { detectWorkflowOverprovisionedSecrets } from "../../src/layer2-static/detectors/workflow-overprovisioned-secrets";

describe("workflow overprovisioned secrets detector", () => {
  it("flags serialization of the full secrets context", () => {
    const findings = detectWorkflowOverprovisionedSecrets({
      filePath: ".github/workflows/deploy.yml",
      textContent: [
        "jobs:",
        "  deploy:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: ./deploy.sh",
        "        env:",
        "          SECRETS: ${{ toJSON(secrets) }}",
        "",
      ].join("\n"),
      parsed: {
        on: ["push"],
        jobs: {
          deploy: {
            steps: [
              {
                run: "./deploy.sh",
                env: {
                  SECRETS: "${{ toJSON(secrets) }}",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-overprovisioned-secrets");
    expect(findings[0]?.evidence).toContain("toJSON(secrets)");
  });

  it("ignores explicit secret references", () => {
    const findings = detectWorkflowOverprovisionedSecrets({
      filePath: ".github/workflows/deploy.yml",
      textContent: [
        "jobs:",
        "  deploy:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: ./deploy.sh",
        "        env:",
        "          SECRET_ONE: ${{ secrets.SECRET_ONE }}",
        "",
      ].join("\n"),
      parsed: {
        on: ["push"],
        jobs: {
          deploy: {
            steps: [
              {
                run: "./deploy.sh",
                env: {
                  SECRET_ONE: "${{ secrets.SECRET_ONE }}",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(0);
  });
});
