import { describe, expect, it } from "vitest";
import { createCli } from "../../src/cli";

function renderHelp(args: string[]): string {
  const cli = createCli("9.9.9");
  const output: string[] = [];
  cli.exitOverride();
  const originalStdoutWrite = process.stdout.write.bind(process.stdout);
  const originalStderrWrite = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: string | Uint8Array) => {
    output.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    output.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    return true;
  }) as typeof process.stderr.write;

  try {
    cli.parse(args, { from: "user" });
  } catch {
    // Commander throws after displaying help when exitOverride is enabled.
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
  }

  return output.join("");
}

describe("cli help examples", () => {
  it("shows GitHub URL scan examples in root help", () => {
    const help = renderHelp(["--help"]);

    expect(help).toContain("Examples:");
    expect(help).toContain("codegate scan https://github.com/owner/repo");
  });

  it("shows scan examples for local and remote targets", () => {
    const help = renderHelp(["scan", "--help"]);

    expect(help).toContain("Scan a local path or URL target for AI tool config risks");
    expect(help).toContain("Examples:");
    expect(help).toContain("codegate scan .");
    expect(help).toContain("codegate scan ./skills/security-review/SKILL.md");
    expect(help).toContain("codegate scan https://github.com/owner/repo");
    expect(help).toContain(
      "codegate scan https://github.com/owner/repo/blob/main/skills/security-review/SKILL.md",
    );
  });

  it("shows run command examples", () => {
    const help = renderHelp(["run", "--help"]);

    expect(help).toContain("Examples:");
    expect(help).toContain("codegate run claude");
    expect(help).toContain("codegate run codex --force");
  });

  it("shows undo command examples", () => {
    const help = renderHelp(["undo", "--help"]);

    expect(help).toContain("Examples:");
    expect(help).toContain("codegate undo");
    expect(help).toContain("codegate undo ./project");
  });

  it("shows init command examples", () => {
    const help = renderHelp(["init", "--help"]);

    expect(help).toContain("Examples:");
    expect(help).toContain("codegate init");
    expect(help).toContain("codegate init --path ./.codegate/config.json");
    expect(help).toContain("codegate init --force");
  });

  it("shows update-kb command examples", () => {
    const help = renderHelp(["update-kb", "--help"]);

    expect(help).toContain("Examples:");
    expect(help).toContain("codegate update-kb");
  });

  it("shows update-rules command examples", () => {
    const help = renderHelp(["update-rules", "--help"]);

    expect(help).toContain("Examples:");
    expect(help).toContain("codegate update-rules");
  });
});
