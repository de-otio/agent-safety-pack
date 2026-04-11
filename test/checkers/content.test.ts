import { describe, expect, it } from "vitest";
import { scanContent } from "../../src/checkers/content.js";
import type { CompiledPatternSet } from "../../src/patterns/loader.js";

function makeSet(patterns: string[]): CompiledPatternSet {
  return {
    name: "test-patterns",
    patterns: patterns.map((p) => ({ source: p, regex: new RegExp(p, "im") })),
  };
}

describe("scanContent", () => {
  it("returns allow for content with no matches", () => {
    const set = makeSet(["AKIA[0-9A-Z]{16}", "password\\s*=\\s*\\S+"]);
    const result = scanContent("hello world", set);
    expect(result.decision).toBe("allow");
    expect(result.matchedPatterns).toHaveLength(0);
    expect(result.matchCount).toBe(0);
  });

  it("returns deny and lists all matching patterns", () => {
    const set = makeSet(["secret_key", "api_token"]);
    const result = scanContent("secret_key=abc\napi_token=xyz", set);
    expect(result.decision).toBe("deny");
    expect(result.matchedPatterns).toContain("secret_key");
    expect(result.matchedPatterns).toContain("api_token");
    expect(result.matchCount).toBe(2);
  });

  it("returns allow for empty content", () => {
    const set = makeSet(["secret"]);
    const result = scanContent("", set);
    expect(result.decision).toBe("allow");
  });

  it("includes reason when patterns match", () => {
    const set = makeSet(["secret"]);
    const result = scanContent("secret here", set);
    expect(result.reason).toContain("1 pattern");
  });

  it("never returns ask", () => {
    const set = makeSet(["secret"]);
    const result = scanContent("secret here", set);
    expect(result.decision).not.toBe("ask");
  });

  it("handles multiline content with im flags", () => {
    const set = makeSet(["^API_KEY=[A-Za-z0-9]+$"]);
    const result = scanContent("some text\nAPI_KEY=abc123\nmore text", set);
    expect(result.decision).toBe("deny");
  });
});
