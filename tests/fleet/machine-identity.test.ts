import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { machineIdPath, resolveMachineId } from "../../src/fleet/machine-identity";

function tempHome(): string {
  return mkdtempSync(join(tmpdir(), "codegate-machine-id-"));
}

describe("resolveMachineId", () => {
  it("mints an id on first use and persists it", () => {
    const home = tempHome();
    const id = resolveMachineId({ homeDir: () => home });

    expect(id).not.toBe("");
    expect(readFileSync(machineIdPath({ homeDir: () => home }), "utf8").trim()).toBe(id);
  });

  it("returns the same id on every later call", () => {
    const home = tempHome();
    const first = resolveMachineId({ homeDir: () => home });
    const second = resolveMachineId({ homeDir: () => home });

    expect(second).toBe(first);
  });

  // The id correlates every report from a machine; it should not be world-readable.
  // POSIX modes do not exist on Windows, so this is asserted where the
  // guarantee is real rather than weakened everywhere to accommodate one
  // platform.
  it.skipIf(process.platform === "win32")("writes the id readable only by its owner", () => {
    const home = tempHome();
    resolveMachineId({ homeDir: () => home });

    const mode = statSync(machineIdPath({ homeDir: () => home })).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("tolerates surrounding whitespace in an existing file", () => {
    const home = tempHome();
    mkdirSync(join(home, ".codegate"), { recursive: true });
    writeFileSync(machineIdPath({ homeDir: () => home }), "  abc-123  \n");

    expect(resolveMachineId({ homeDir: () => home })).toBe("abc-123");
  });

  // A lost identity cannot be repaired; refusing to report would be worse.
  it("replaces an empty or corrupt id rather than failing", () => {
    const home = tempHome();
    mkdirSync(join(home, ".codegate"), { recursive: true });
    writeFileSync(machineIdPath({ homeDir: () => home }), "   \n");

    const id = resolveMachineId({ homeDir: () => home });
    expect(id).not.toBe("");
    expect(id.trim()).toBe(id);
  });

  it("replaces an id containing unusable characters", () => {
    const home = tempHome();
    mkdirSync(join(home, ".codegate"), { recursive: true });
    writeFileSync(machineIdPath({ homeDir: () => home }), "not a valid id!\n");

    const id = resolveMachineId({ homeDir: () => home, generateId: () => "replacement-1" });
    expect(id).toBe("replacement-1");
  });

  it("falls back to a real uuid when the generator returns something unusable", () => {
    const home = tempHome();
    const id = resolveMachineId({ homeDir: () => home, generateId: () => "  " });

    expect(id.length).toBeGreaterThan(10);
    expect(id).toMatch(/^[0-9a-f-]+$/);
  });

  it("creates the codegate directory when it does not exist", () => {
    const home = tempHome();
    const id = resolveMachineId({ homeDir: () => home });

    expect(readFileSync(join(home, ".codegate", "machine-id"), "utf8").trim()).toBe(id);
  });
});
