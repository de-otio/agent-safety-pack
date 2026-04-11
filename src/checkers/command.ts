import type { CompiledPatternSet } from "../patterns/loader.js";
import { matchFirst } from "../patterns/matcher.js";
// src/checkers/command.ts
import type { CheckResult } from "../types.js";

/**
 * Check a shell command against deny patterns.
 * Returns deny on first match, allow otherwise.
 * No 'ask' results — commands are either blocked or allowed.
 *
 * Note: bash-deny.txt is compiled with the 'i' flag (case-insensitive),
 * so 'RM -RF /' matches the same as 'rm -rf /'.
 */
export function checkCommand(command: string, patterns: CompiledPatternSet): CheckResult {
  if (!command || typeof command !== "string") {
    return { decision: "allow" };
  }

  const match = matchFirst(command, patterns);
  if (match.matched) {
    return {
      decision: "deny",
      matchedPattern: match.pattern,
      source: "bash-deny",
      reason: `Command matches deny pattern: ${match.pattern}`,
    };
  }

  return { decision: "allow" };
}
