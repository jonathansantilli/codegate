import { describe, expect, it } from "vitest";
import { toAbsoluteDisplayPath } from "../src/path-display";

describe("path display", () => {
  it("keeps user-scope tilde paths out of the scan target prefix", () => {
    expect(
      toAbsoluteDisplayPath("/tmp/codegate-case3", "~/.codex/skills/writing-plans/SKILL.md"),
    ).toBe("~/.codex/skills/writing-plans/SKILL.md");
  });

  it("keeps URI-like resource identifiers unchanged", () => {
    expect(toAbsoluteDisplayPath("/tmp/codegate-case3", "https://mcp.linear.app/mcp")).toBe(
      "https://mcp.linear.app/mcp",
    );
  });
});
