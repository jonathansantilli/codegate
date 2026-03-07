import { describe, expect, it } from "vitest";
import { detectSymlinkEscapes } from "../../src/layer2-static/detectors/symlink";

describe("task 13 symlink detector", () => {
  it("flags symlink escapes outside project root", () => {
    const findings = detectSymlinkEscapes({
      symlinkEscapes: [
        {
          path: "/tmp/project/link",
          target: "/Users/tester/.aws/credentials",
        },
      ],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("HIGH");
  });
});
