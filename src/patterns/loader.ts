// src/patterns/loader.ts
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";

export interface CompiledPattern {
  source: string;
  regex: RegExp;
}

export interface CompiledPatternSet {
  name: string;
  patterns: CompiledPattern[];
}

function compilePatterns(name: string, content: string, flags: string): CompiledPatternSet {
  const lines = content.split("\n");
  const compiled: CompiledPattern[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Strip inline (?i) flag prefix — handled by file-level flags
    const pattern = trimmed.replace(/^\(\?i\)/, "");

    try {
      compiled.push({ source: pattern, regex: new RegExp(pattern, flags) });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(
        `[agent-safety-pack] Invalid pattern in ${name} (line ${i + 1}): ${msg} — pattern: ${pattern}`,
      );
    }
  }

  return { name, patterns: compiled };
}

export function loadPatternFile(filePath: string, flags = ""): CompiledPatternSet {
  const name = filePath.split("/").pop()?.replace(".txt", "") ?? filePath;
  const content = readFileSync(filePath, "utf-8");
  return compilePatterns(name, content, flags);
}

export async function loadPatternFileAsync(
  filePath: string,
  flags = "",
): Promise<CompiledPatternSet> {
  const name = filePath.split("/").pop()?.replace(".txt", "") ?? filePath;
  const content = await readFile(filePath, "utf-8");
  return compilePatterns(name, content, flags);
}
