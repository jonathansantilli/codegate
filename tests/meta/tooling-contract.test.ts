import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd());

function readPackageJson(): {
  scripts?: Record<string, string>;
  engines?: Record<string, string>;
  "lint-staged"?: Record<string, string[] | string>;
  devDependencies?: Record<string, string>;
  bin?: Record<string, string>;
} {
  const content = readFileSync(resolve(root, "package.json"), "utf8");
  return JSON.parse(content) as {
    scripts?: Record<string, string>;
    engines?: Record<string, string>;
    "lint-staged"?: Record<string, string[] | string>;
    devDependencies?: Record<string, string>;
    bin?: Record<string, string>;
  };
}

describe("task 02 tooling contract", () => {
  it("defines required npm scripts", () => {
    const scripts = readPackageJson().scripts ?? {};
    expect(scripts).toHaveProperty("lint");
    expect(scripts).toHaveProperty("typecheck");
    expect(scripts).toHaveProperty("test");
    expect(scripts).toHaveProperty("prepare");
  });

  it("contains required config files", () => {
    expect(existsSync(resolve(root, "eslint.config.js"))).toBe(true);
    expect(existsSync(resolve(root, ".prettierrc"))).toBe(true);
    expect(existsSync(resolve(root, "vitest.config.ts"))).toBe(true);
    expect(existsSync(resolve(root, "tests/setup.ts"))).toBe(true);
  });

  it("declares a node engine compatible with latest toolchain", () => {
    const nodeEngine = readPackageJson().engines?.node ?? "";
    expect(nodeEngine).toContain("20");
    expect(nodeEngine).toContain("22");
  });

  it("configures a pre-commit hook for staged linting and formatting", () => {
    const packageJson = readPackageJson();
    expect(packageJson.devDependencies).toHaveProperty("husky");
    expect(packageJson.devDependencies).toHaveProperty("lint-staged");
    expect(packageJson["lint-staged"]).toBeTruthy();
    expect(existsSync(resolve(root, ".husky/pre-commit"))).toBe(true);
    expect(readFileSync(resolve(root, ".husky/pre-commit"), "utf8")).toContain("lint-staged");
  });

  it("exposes both codegate and codegate-ai CLI bin aliases", () => {
    const bin = readPackageJson().bin ?? {};
    expect(bin).toHaveProperty("codegate", "dist/cli.js");
    expect(bin).toHaveProperty("codegate-ai", "dist/cli.js");
  });
});
