import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  fleetConfigPath,
  resolveFleetConfig,
  SERVER_ENV,
  TOKEN_ENV,
} from "../../src/fleet/fleet-config";

function tempHome(): string {
  return mkdtempSync(join(tmpdir(), "codegate-fleet-config-"));
}

function writeConfig(home: string, body: unknown): void {
  mkdirSync(join(home, ".codegate"), { recursive: true });
  writeFileSync(fleetConfigPath({ homeDir: () => home }), JSON.stringify(body));
}

const EMPTY_ENV = {} as NodeJS.ProcessEnv;

describe("resolveFleetConfig", () => {
  it("reads server and token from the environment", () => {
    const result = resolveFleetConfig({
      homeDir: tempHome,
      env: {
        [SERVER_ENV]: "https://guardian.acme.internal",
        [TOKEN_ENV]: "t-1",
      } as NodeJS.ProcessEnv,
    });

    expect(result).toEqual({
      ok: true,
      config: { server: "https://guardian.acme.internal", token: "t-1" },
    });
  });

  // The file is how MDM configures a whole fleet without touching shells.
  it("reads server and token from the config file", () => {
    const home = tempHome();
    writeConfig(home, { server: "https://guardian.acme.internal", token: "t-file" });

    const result = resolveFleetConfig({ homeDir: () => home, env: EMPTY_ENV });
    expect(result).toEqual({
      ok: true,
      config: { server: "https://guardian.acme.internal", token: "t-file" },
    });
  });

  it("lets the environment override the file", () => {
    const home = tempHome();
    writeConfig(home, { server: "https://file.example", token: "t-file" });

    const result = resolveFleetConfig({
      homeDir: () => home,
      env: { [SERVER_ENV]: "https://env.example", [TOKEN_ENV]: "t-env" } as NodeJS.ProcessEnv,
    });
    expect(result).toEqual({ ok: true, config: { server: "https://env.example", token: "t-env" } });
  });

  it("trims a trailing slash so paths join predictably", () => {
    const result = resolveFleetConfig({
      homeDir: tempHome,
      env: {
        [SERVER_ENV]: "https://guardian.acme.internal/",
        [TOKEN_ENV]: "t",
      } as NodeJS.ProcessEnv,
    });
    expect(result).toEqual({
      ok: true,
      config: { server: "https://guardian.acme.internal", token: "t" },
    });
  });

  // Every failure must name what to set and where — an operator should never
  // have to read the source to configure this.
  it("explains what to do when nothing is configured", () => {
    const result = resolveFleetConfig({ homeDir: tempHome, env: EMPTY_ENV });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain(SERVER_ENV);
    expect(result.reason).toContain(TOKEN_ENV);
    expect(result.reason).toContain("fleet.json");
  });

  it("names the missing half when only the token is set", () => {
    const result = resolveFleetConfig({
      homeDir: tempHome,
      env: { [TOKEN_ENV]: "t" } as NodeJS.ProcessEnv,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain(SERVER_ENV);
  });

  it("names the missing half when only the server is set", () => {
    const result = resolveFleetConfig({
      homeDir: tempHome,
      env: { [SERVER_ENV]: "https://g.example" } as NodeJS.ProcessEnv,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain(TOKEN_ENV);
  });

  it("rejects a server that is not an absolute http(s) URL", () => {
    for (const bad of ["guardian.acme.internal", "ftp://g.example", "/guardian", "not a url"]) {
      const result = resolveFleetConfig({
        homeDir: tempHome,
        env: { [SERVER_ENV]: bad, [TOKEN_ENV]: "t" } as NodeJS.ProcessEnv,
      });
      expect(result.ok, bad).toBe(false);
    }
  });

  it("accepts a server behind a path prefix", () => {
    const result = resolveFleetConfig({
      homeDir: tempHome,
      env: {
        [SERVER_ENV]: "https://acme.internal/guardian",
        [TOKEN_ENV]: "t",
      } as NodeJS.ProcessEnv,
    });
    expect(result).toEqual({
      ok: true,
      config: { server: "https://acme.internal/guardian", token: "t" },
    });
  });

  it("ignores a malformed config file instead of crashing", () => {
    const home = tempHome();
    mkdirSync(join(home, ".codegate"), { recursive: true });
    writeFileSync(fleetConfigPath({ homeDir: () => home }), "{ not json");

    const result = resolveFleetConfig({ homeDir: () => home, env: EMPTY_ENV });
    expect(result.ok).toBe(false);
  });

  it("ignores blank values in the config file", () => {
    const home = tempHome();
    writeConfig(home, { server: "   ", token: "   " });

    const result = resolveFleetConfig({ homeDir: () => home, env: EMPTY_ENV });
    expect(result.ok).toBe(false);
  });
});
