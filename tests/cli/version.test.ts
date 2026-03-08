import { describe, expect, it } from "vitest";
import { createCli } from "../../src/cli";

describe("cli --version and --help wiring", () => {
  it("configures version and help options", () => {
    const cli = createCli("9.9.9");

    expect(cli.version()).toContain("9.9.9");
    expect(cli.version()).toContain("kb");
    expect(cli.helpInformation()).toContain("-h, --help");
    expect(cli.helpInformation()).toContain("-V, --version");
  });
});
