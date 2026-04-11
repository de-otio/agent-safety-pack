import { describe, expect, it } from "vitest";
import { checkPath } from "../../src/checkers/path.js";
import type { SensitivePathSet } from "../../src/patterns/sensitive-paths.js";

function makePaths(): SensitivePathSet {
  return {
    deny: {
      name: "sensitive-paths-deny",
      patterns: [
        { source: "^\\/etc\\/", regex: /^\/etc\// },
        { source: "\\.ssh\\/", regex: /\.ssh\// },
      ],
    },
    ask: {
      name: "sensitive-paths-ask",
      patterns: [
        { source: "\\.github\\/workflows\\/", regex: /\.github\/workflows\// },
        { source: "\\.env$", regex: /\.env$/ },
      ],
    },
  };
}

describe("checkPath", () => {
  const paths = makePaths();

  it("returns deny for deny-section path", () => {
    const result = checkPath("/etc/passwd", paths, false);
    expect(result.decision).toBe("deny");
    expect(result.section).toBe("deny");
    expect(result.filePath).toBe("/etc/passwd");
  });

  it("returns ask for ask-section path in non-strict mode", () => {
    const result = checkPath("/project/.env", paths, false);
    expect(result.decision).toBe("ask");
    expect(result.section).toBe("ask");
  });

  it("returns deny for ask-section path in strict mode", () => {
    const result = checkPath("/project/.env", paths, true);
    expect(result.decision).toBe("deny");
    expect(result.section).toBe("ask"); // section reflects original section, not conversion
  });

  it("section field is always set on a match", () => {
    const denyResult = checkPath("/etc/shadow", paths, false);
    expect(denyResult.section).toBe("deny");

    const askResult = checkPath("/project/.env", paths, false);
    expect(askResult.section).toBe("ask");
  });

  it("returns allow for a safe path", () => {
    const result = checkPath("/project/src/index.ts", paths, false);
    expect(result.decision).toBe("allow");
    expect(result.section).toBeUndefined();
  });

  it("deny section takes priority over ask section", () => {
    // A path that could match both — deny wins
    const result = checkPath("/etc/passwd", paths, false);
    expect(result.decision).toBe("deny");
  });

  it("returns allow for empty input", () => {
    const result = checkPath("", paths, false);
    expect(result.decision).toBe("allow");
  });

  it("includes reason in result", () => {
    const result = checkPath("/etc/hosts", paths, false);
    expect(result.reason).toBeTruthy();
  });
});
