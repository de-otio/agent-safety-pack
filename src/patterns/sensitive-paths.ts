// src/patterns/sensitive-paths.ts
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import type { CompiledPattern, CompiledPatternSet } from "./loader.js";

export interface SensitivePathSet {
  deny: CompiledPatternSet;
  ask: CompiledPatternSet;
}

const ASK_MARKER = "# === ASK ===";

function parsePathFile(filePath: string, content: string): SensitivePathSet {
  const lines = content.split("\n");
  let section: "deny" | "ask" = "deny";

  const denyPatterns: CompiledPattern[] = [];
  const askPatterns: CompiledPattern[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    const trimmed = line.trim();

    if (trimmed.startsWith(ASK_MARKER)) {
      section = "ask";
      continue;
    }

    if (!trimmed || trimmed.startsWith("#")) continue;

    try {
      const compiled: CompiledPattern = { source: trimmed, regex: new RegExp(trimmed) };
      if (section === "deny") {
        denyPatterns.push(compiled);
      } else {
        askPatterns.push(compiled);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(
        `[agent-safety-pack] Invalid path pattern (line ${i + 1}): ${msg} — pattern: ${trimmed}`,
      );
    }
  }

  return {
    deny: { name: "sensitive-paths-deny", patterns: denyPatterns },
    ask: { name: "sensitive-paths-ask", patterns: askPatterns },
  };
}

export function loadSensitivePaths(filePath: string): SensitivePathSet {
  const content = readFileSync(filePath, "utf-8");
  return parsePathFile(filePath, content);
}

export async function loadSensitivePathsAsync(filePath: string): Promise<SensitivePathSet> {
  const content = await readFile(filePath, "utf-8");
  return parsePathFile(filePath, content);
}
