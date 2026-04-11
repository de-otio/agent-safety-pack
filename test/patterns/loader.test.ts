import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadPatternFile, loadPatternFileAsync } from "../../src/patterns/loader.js";

function writeTmp(name: string, content: string): string {
  const dir = join(tmpdir(), `asp-test-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, name);
  writeFileSync(path, content, "utf-8");
  return path;
}

describe("loadPatternFile", () => {
  it("loads and compiles valid patterns", () => {
    const path = writeTmp("test.txt", "# comment\n\\beval\\b\n^rm\\b");
    const set = loadPatternFile(path);
    expect(set.patterns).toHaveLength(2);
    expect(set.patterns[0]?.source).toBe("\\beval\\b");
  });

  it("skips blank lines and comments", () => {
    const path = writeTmp("test.txt", "\n# comment\n\n\\btest\\b\n");
    const set = loadPatternFile(path);
    expect(set.patterns).toHaveLength(1);
  });

  it("strips (?i) prefix from patterns", () => {
    const path = writeTmp("test.txt", "(?i)\\bEVAL\\b");
    const set = loadPatternFile(path, "i");
    expect(set.patterns[0]?.source).toBe("\\bEVAL\\b");
  });

  it("skips invalid patterns without throwing", () => {
    const path = writeTmp("test.txt", "\\bvalid\\b\n[invalid");
    const set = loadPatternFile(path);
    expect(set.patterns).toHaveLength(1);
  });

  it("applies flags to compiled patterns", () => {
    const path = writeTmp("test.txt", "hello");
    const set = loadPatternFile(path, "i");
    expect(set.patterns[0]?.regex.flags).toContain("i");
  });
});

describe("loadPatternFileAsync", () => {
  it("async load returns same result as sync", async () => {
    const path = writeTmp("test.txt", "# comment\n\\beval\\b");
    const sync = loadPatternFile(path);
    const async_ = await loadPatternFileAsync(path);
    expect(async_.patterns).toHaveLength(sync.patterns.length);
    expect(async_.patterns[0]?.source).toBe(sync.patterns[0]?.source);
  });
});
