import { describe, expect, it } from "vitest";
import { checkSearchQuery } from "../../src/checkers/search-query.js";
import type { CompiledPatternSet } from "../../src/patterns/loader.js";

function makeSet(patterns: string[]): CompiledPatternSet {
  return {
    name: "websearch-leak-patterns",
    patterns: patterns.map((p) => ({ source: p, regex: new RegExp(p, "im") })),
  };
}

describe("checkSearchQuery", () => {
  it("returns allow for a safe query", () => {
    const set = makeSet(["AKIA[0-9A-Z]{16}"]);
    const result = checkSearchQuery("how to use typescript generics", set);
    expect(result.decision).toBe("allow");
  });

  it("returns deny when query contains a secret pattern", () => {
    const set = makeSet(["AKIA[0-9A-Z]{16}"]);
    const result = checkSearchQuery("AKIAIOSFODNN7EXAMPLE how to use this", set);
    expect(result.decision).toBe("deny");
  });
});
