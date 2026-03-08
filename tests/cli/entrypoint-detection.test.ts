import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { isDirectCliInvocation } from "../../src/cli";

describe("cli entrypoint detection", () => {
  it("treats a symlinked argv[1] path as a direct invocation", () => {
    const realEntryPath = resolve("tmp", "codegate-ai", "dist", "cli.js");
    const importMetaUrl = pathToFileURL(realEntryPath).href;
    const argv1 = resolve("tmp", "bin", "codegate");

    const direct = isDirectCliInvocation(importMetaUrl, argv1, {
      realpath: () => realEntryPath,
    });

    expect(direct).toBe(true);
  });

  it("returns false when argv[1] does not resolve to the module file", () => {
    const realEntryPath = resolve("tmp", "codegate-ai", "dist", "cli.js");
    const otherPath = resolve("tmp", "codegate-ai", "dist", "other.js");
    const importMetaUrl = pathToFileURL(realEntryPath).href;
    const argv1 = resolve("tmp", "bin", "other-cli");

    const direct = isDirectCliInvocation(importMetaUrl, argv1, {
      realpath: () => otherPath,
    });

    expect(direct).toBe(false);
  });
});
