import { describe, expect, it } from "vitest";
import { isDirectCliInvocation } from "../../src/cli";

describe("cli entrypoint detection", () => {
  it("treats a symlinked argv[1] path as a direct invocation", () => {
    const importMetaUrl = "file:///usr/local/lib/node_modules/codegate-ai/dist/cli.js";
    const argv1 = "/usr/local/bin/codegate";

    const direct = isDirectCliInvocation(importMetaUrl, argv1, {
      realpath: () => "/usr/local/lib/node_modules/codegate-ai/dist/cli.js",
    });

    expect(direct).toBe(true);
  });

  it("returns false when argv[1] does not resolve to the module file", () => {
    const importMetaUrl = "file:///usr/local/lib/node_modules/codegate-ai/dist/cli.js";
    const argv1 = "/usr/local/bin/other-cli";

    const direct = isDirectCliInvocation(importMetaUrl, argv1, {
      realpath: () => "/usr/local/lib/node_modules/codegate-ai/dist/other.js",
    });

    expect(direct).toBe(false);
  });
});
