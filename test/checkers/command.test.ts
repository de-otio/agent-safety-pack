import { describe, expect, it } from "vitest";
import { checkCommand } from "../../src/checkers/command.js";
import type { CompiledPatternSet } from "../../src/patterns/loader.js";

function makePatterns(patterns: string[]): CompiledPatternSet {
  return {
    name: "bash-deny",
    patterns: patterns.map((p) => ({ source: p, regex: new RegExp(p, "i") })),
  };
}

describe("checkCommand", () => {
  const patterns = makePatterns(["\\brm\\b.*-rf", "\\beval\\b", "\\bsudo\\b"]);

  it("returns deny for a matching command", () => {
    const result = checkCommand("rm -rf /", patterns);
    expect(result.decision).toBe("deny");
    expect(result.source).toBe("bash-deny");
    expect(result.matchedPattern).toBeTruthy();
  });

  it("returns allow for a safe command", () => {
    const result = checkCommand("ls -la", patterns);
    expect(result.decision).toBe("allow");
  });

  it("is case-insensitive (i flag on patterns)", () => {
    const result = checkCommand("RM -RF /", patterns);
    expect(result.decision).toBe("deny");
  });

  it("returns allow for empty input", () => {
    const result = checkCommand("", patterns);
    expect(result.decision).toBe("allow");
  });

  it("includes reason in result", () => {
    const result = checkCommand("eval $payload", patterns);
    expect(result.decision).toBe("deny");
    expect(result.reason).toContain("deny pattern");
  });

  it("never returns ask", () => {
    const result = checkCommand("rm -rf /", patterns);
    expect(result.decision).not.toBe("ask");
  });

  it("SECURITY: matches POSIX dot-source (. .env) — fixed from \\b dot issue", () => {
    const dotSourcePatterns = makePatterns(["(^|[\\s;&|])\\.\\s+.*\\.env\\b"]);
    expect(checkCommand(". .env", dotSourcePatterns).decision).toBe("deny");
    expect(checkCommand(". ./.env", dotSourcePatterns).decision).toBe("deny");
    expect(checkCommand("cmd && . .env", dotSourcePatterns).decision).toBe("deny");
  });
});
