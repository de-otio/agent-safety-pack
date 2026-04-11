import { describe, expect, it } from "vitest";
import type { CompiledPatternSet } from "../../src/patterns/loader.js";
import { matchAll, matchFirst } from "../../src/patterns/matcher.js";

function makeSet(patterns: string[], flags = ""): CompiledPatternSet {
  return {
    name: "test",
    patterns: patterns.map((p) => ({ source: p, regex: new RegExp(p, flags) })),
  };
}

describe("matchFirst", () => {
  it("returns matched=true and the pattern on first match", () => {
    const set = makeSet(["\\beval\\b", "^rm"]);
    const result = matchFirst("eval something", set);
    expect(result.matched).toBe(true);
    expect(result.pattern).toBe("\\beval\\b");
  });

  it("returns matched=false when nothing matches", () => {
    const set = makeSet(["\\beval\\b"]);
    const result = matchFirst("ls -la", set);
    expect(result.matched).toBe(false);
    expect(result.pattern).toBeUndefined();
  });

  it("returns on first match without checking subsequent patterns", () => {
    const set = makeSet(["\\beval\\b", "\\bsecret\\b"]);
    const result = matchFirst("eval secret", set);
    expect(result.pattern).toBe("\\beval\\b");
  });
});

describe("matchAll", () => {
  it("returns all matching patterns", () => {
    const set = makeSet(["\\beval\\b", "\\bsecret\\b", "^rm"]);
    const result = matchAll("eval secret here", set);
    expect(result.matched).toBe(true);
    expect(result.patterns).toContain("\\beval\\b");
    expect(result.patterns).toContain("\\bsecret\\b");
    expect(result.count).toBe(2);
  });

  it("returns empty arrays when nothing matches", () => {
    const set = makeSet(["\\beval\\b"]);
    const result = matchAll("ls -la", set);
    expect(result.matched).toBe(false);
    expect(result.patterns).toHaveLength(0);
    expect(result.count).toBe(0);
  });

  it("resets lastIndex for global-flagged patterns", () => {
    const set = makeSet(["\\bword\\b"], "g");
    // Call twice to ensure lastIndex reset works
    matchAll("word here", set);
    const result = matchAll("word here", set);
    expect(result.matched).toBe(true);
  });
});
