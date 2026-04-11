import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadSensitivePaths } from "../../src/patterns/sensitive-paths.js";

function writeTmp(content: string): string {
  const dir = join(tmpdir(), `asp-paths-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "sensitive-paths.txt");
  writeFileSync(path, content, "utf-8");
  return path;
}

const fixture = `# deny section
^\\/etc\\/
^\\/root\\/
# === ASK ===
# ask section
\\.github\\/workflows\\/
\\.env$`;

describe("loadSensitivePaths", () => {
  it("splits patterns into deny and ask sections", () => {
    const path = writeTmp(fixture);
    const set = loadSensitivePaths(path);
    expect(set.deny.patterns.length).toBeGreaterThan(0);
    expect(set.ask.patterns.length).toBeGreaterThan(0);
  });

  it("deny patterns match deny-section paths", () => {
    const path = writeTmp(fixture);
    const set = loadSensitivePaths(path);
    const matched = set.deny.patterns.some((p) => p.regex.test("/etc/passwd"));
    expect(matched).toBe(true);
  });

  it("ask patterns match ask-section paths", () => {
    const path = writeTmp(fixture);
    const set = loadSensitivePaths(path);
    const matched = set.ask.patterns.some((p) => p.regex.test(".github/workflows/ci.yml"));
    expect(matched).toBe(true);
  });

  it("deny patterns do not include ask-section patterns", () => {
    const path = writeTmp(fixture);
    const set = loadSensitivePaths(path);
    const deniesWorkflow = set.deny.patterns.some((p) => p.regex.test(".github/workflows/ci.yml"));
    expect(deniesWorkflow).toBe(false);
  });

  it("skips comments and blank lines in both sections", () => {
    const path = writeTmp(fixture);
    const set = loadSensitivePaths(path);
    // No pattern should be the comment text
    const allSources = [
      ...set.deny.patterns.map((p) => p.source),
      ...set.ask.patterns.map((p) => p.source),
    ];
    expect(allSources.every((s) => !s.startsWith("#"))).toBe(true);
  });
});
