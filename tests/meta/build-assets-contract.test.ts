import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());

describe("build asset contract", () => {
  it("keeps runtime asset copy step in build script", () => {
    const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
      scripts?: Record<string, string>;
    };
    expect(packageJson.scripts?.build).toContain("copy-assets");
    expect(existsSync(resolve(root, "scripts/copy-assets.mjs"))).toBe(true);
  });
});
