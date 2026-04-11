import type { CompiledPatternSet } from "../patterns/loader.js";
import { matchAll } from "../patterns/matcher.js";
// src/checkers/content.ts
import type { ContentCheckResult } from "../types.js";

/**
 * Scan content for all matching patterns.
 * Unlike command/URL checks which short-circuit on first match,
 * content scanning collects ALL matches — callers need the complete picture.
 *
 * Used for:
 *   - checkContentSecrets: scans against secrets-patterns.txt
 *   - checkContentInjection: scans against injection-patterns.txt
 *
 * Note: these checks run post-execution. The action has already completed;
 * this function flags dangerous content but cannot undo the completed action.
 */
export function scanContent(content: string, patternSet: CompiledPatternSet): ContentCheckResult {
  if (!content || typeof content !== "string") {
    return { decision: "allow", matchedPatterns: [], matchCount: 0 };
  }

  const result = matchAll(content, patternSet);

  if (result.matched) {
    return {
      decision: "deny",
      matchedPatterns: result.patterns,
      matchCount: result.count,
      source: patternSet.name,
      reason: `${result.count} pattern(s) matched in content`,
      matchedPattern: result.pattern,
    };
  }

  return { decision: "allow", matchedPatterns: [], matchCount: 0 };
}
