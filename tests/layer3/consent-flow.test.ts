import { describe, expect, it, vi } from "vitest";
import { runDeepScanWithConsent, type DeepScanResource } from "../../src/pipeline";

const RESOURCES: DeepScanResource[] = [
  {
    id: "npm:@org/package",
    request: { id: "npm:@org/package", kind: "npm", locator: "@org/package" },
    commandPreview: "fetch npm metadata",
  },
  {
    id: "http:https://example.com",
    request: { id: "http:https://example.com", kind: "http", locator: "https://example.com" },
    commandPreview: "fetch remote metadata",
  },
];

describe("task 26 deep scan consent flow", () => {
  it("does not execute deep-scan fetch without explicit approval", async () => {
    const execute = vi.fn(async () => ({
      status: "ok" as const,
      attempts: 1,
      elapsedMs: 1,
      metadata: { value: "ok" },
    }));

    const outcomes = await runDeepScanWithConsent(
      RESOURCES,
      async (resource) => resource.id === "http:https://example.com",
      execute,
    );

    expect(execute).toHaveBeenCalledTimes(1);
    expect(outcomes[0]?.status).toBe("skipped_without_consent");
    expect(outcomes[1]?.status).toBe("ok");
  });
});
