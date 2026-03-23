import { describe, expect, it } from "vitest";
import { detectWorkflowSecretsOutsideEnv } from "../../src/layer2-static/detectors/workflow-secrets-outside-env";

describe("workflow secrets outside environment detector", () => {
  it("flags secret usage in jobs without an environment", () => {
    const findings = detectWorkflowSecretsOutsideEnv({
      filePath: ".github/workflows/deploy.yml",
      textContent: [
        "jobs:",
        "  deploy:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: ./deploy.sh",
        "        env:",
        "          API_KEY: ${{ secrets.API_KEY }}",
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
                  API_KEY: "${{ secrets.API_KEY }}",
                },
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule_id).toBe("workflow-secrets-outside-env");
    expect(findings[0]?.evidence).toContain("secrets.API_KEY");
  });

  it("ignores jobs that declare a dedicated environment", () => {
    const findings = detectWorkflowSecretsOutsideEnv({
      filePath: ".github/workflows/deploy.yml",
      textContent: [
        "jobs:",
        "  deploy:",
        "    environment: production",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: ./deploy.sh",
        "        env:",
        "          API_KEY: ${{ secrets.API_KEY }}",
        "",
      ].join("\n"),
      parsed: {
        on: ["push"],
        jobs: {
          deploy: {
            environment: "production",
            steps: [
              {
                run: "./deploy.sh",
                env: {
                  API_KEY: "${{ secrets.API_KEY }}",
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
