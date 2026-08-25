import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { enrolMachine, ENROL_PATH } from "../../src/fleet/enrol-client";
import { fleetConfigPath } from "../../src/fleet/fleet-config";

function tempHome(): string {
  return mkdtempSync(join(tmpdir(), "codegate-enrol-"));
}

function ok(token = "t-issued"): typeof fetch {
  return (async () =>
    new Response(JSON.stringify({ token }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
}

describe("enrolMachine", () => {
  it("exchanges a code for a token and writes the config", async () => {
    const home = tempHome();
    const result = await enrolMachine(
      { server: "https://guardian.acme.internal", code: "FLEET-7K2M-9XQ4" },
      { homeDir: () => home, fetch: ok() },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const written = JSON.parse(readFileSync(fleetConfigPath({ homeDir: () => home }), "utf8"));
    expect(written).toEqual({
      server: "https://guardian.acme.internal",
      token: "t-issued",
    });
  });

  it("posts the code and this machine's id to the enrol endpoint", async () => {
    const home = tempHome();
    let seenUrl = "";
    let body: { code?: string; machineId?: string } = {};

    await enrolMachine(
      { server: "https://guardian.acme.internal", code: "FLEET-7K2M-9XQ4" },
      {
        homeDir: () => home,
        fetch: (async (url: string, init: RequestInit) => {
          seenUrl = url;
          body = JSON.parse(String(init.body));
          return new Response(JSON.stringify({ token: "t" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }) as unknown as typeof fetch,
      },
    );

    expect(seenUrl).toBe(`https://guardian.acme.internal${ENROL_PATH}`);
    expect(body.code).toBe("FLEET-7K2M-9XQ4");
    expect(body.machineId?.length).toBeGreaterThan(0);
  });

  // The token lets this machine report as itself; nobody else on the box needs
  // it. POSIX modes do not exist on Windows — NTFS uses ACLs and Node's chmod
  // cannot express 0600 there — so the assertion is made where the guarantee
  // is real, rather than dropped or weakened everywhere to accommodate one
  // platform. See docs on Windows permissions in the fleet README section.
  it.skipIf(process.platform === "win32")(
    "writes the token readable only by its owner",
    async () => {
      const home = tempHome();
      await enrolMachine(
        { server: "https://guardian.acme.internal", code: "C" },
        { homeDir: () => home, fetch: ok() },
      );

      const mode = statSync(fleetConfigPath({ homeDir: () => home })).mode & 0o777;
      expect(mode).toBe(0o600);
    },
  );

  it("keeps the machine id it already had", async () => {
    const home = tempHome();
    let first = "";
    const capture = (async (_u: string, init: RequestInit) => {
      first ||= JSON.parse(String(init.body)).machineId;
      return new Response(JSON.stringify({ token: "t" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    await enrolMachine(
      { server: "https://g.example", code: "C" },
      { homeDir: () => home, fetch: capture },
    );
    const before = first;
    first = "";
    await enrolMachine(
      { server: "https://g.example", code: "C" },
      { homeDir: () => home, fetch: capture },
    );

    expect(first).toBe(before);
  });

  it("surfaces the server's reason when a code is refused", async () => {
    const result = await enrolMachine(
      { server: "https://g.example", code: "USED" },
      {
        homeDir: tempHome,
        fetch: (async () =>
          new Response(JSON.stringify({ error: "That enrolment code cannot be used." }), {
            status: 403,
            headers: { "content-type": "application/json" },
          })) as unknown as typeof fetch,
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("cannot be used");
  });

  it("reports a server that is not accepting agents", async () => {
    const result = await enrolMachine(
      { server: "https://g.example", code: "C" },
      {
        homeDir: tempHome,
        fetch: (async () =>
          new Response(JSON.stringify({ error: "no ingest token is configured." }), {
            status: 503,
            headers: { "content-type": "application/json" },
          })) as unknown as typeof fetch,
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("ingest token");
  });

  it("rejects a server that is not an absolute http(s) URL", async () => {
    const result = await enrolMachine(
      { server: "guardian.acme.internal", code: "C" },
      { homeDir: tempHome, fetch: ok() },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("absolute http(s) URL");
  });

  it("does not contact the server when the URL is unusable", async () => {
    let called = false;
    await enrolMachine(
      { server: "not a url", code: "C" },
      {
        homeDir: tempHome,
        fetch: (async () => {
          called = true;
          return new Response("{}", { status: 200 });
        }) as unknown as typeof fetch,
      },
    );

    expect(called).toBe(false);
  });

  it("reports an unreachable server plainly", async () => {
    const result = await enrolMachine(
      { server: "https://g.example", code: "C" },
      {
        homeDir: tempHome,
        fetch: (async () => {
          throw new Error("ECONNREFUSED");
        }) as unknown as typeof fetch,
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("could not reach");
  });

  it("does not claim success when no token comes back", async () => {
    const result = await enrolMachine(
      { server: "https://g.example", code: "C" },
      {
        homeDir: tempHome,
        fetch: (async () =>
          new Response(JSON.stringify({}), {
            status: 200,
            headers: { "content-type": "application/json" },
          })) as unknown as typeof fetch,
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("did not return a token");
  });

  it("says so when enrolment worked but the config could not be written", async () => {
    const result = await enrolMachine(
      { server: "https://g.example", code: "C" },
      {
        homeDir: tempHome,
        fetch: ok(),
        writeConfig: () => {
          throw new Error("EACCES");
        },
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("enrolled, but could not write");
  });
});
