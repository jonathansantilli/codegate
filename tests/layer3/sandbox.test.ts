import { describe, expect, it } from "vitest";
import { DEFAULT_SANDBOX_TIMEOUT_MS } from "../../src/layer3-dynamic/sandbox";

describe("layer3 sandbox defaults", () => {
  it("uses a longer default timeout for meta-agent command execution", () => {
    expect(DEFAULT_SANDBOX_TIMEOUT_MS).toBe(30_000);
  });
});
