// src/patterns/matcher.ts
import type { CompiledPatternSet } from "./loader.js";

export interface MatchResult {
  matched: boolean;
  pattern?: string;
}

export interface MultiMatchResult {
  matched: boolean;
  pattern?: string;
  patterns: string[];
  count: number;
}

export function matchFirst(value: string, patternSet: CompiledPatternSet): MatchResult {
  for (const { source, regex } of patternSet.patterns) {
    regex.lastIndex = 0;
    if (regex.test(value)) {
      return { matched: true, pattern: source };
    }
  }
  return { matched: false };
}

export function matchAll(value: string, patternSet: CompiledPatternSet): MultiMatchResult {
  const matched: string[] = [];

  for (const { source, regex } of patternSet.patterns) {
    regex.lastIndex = 0;
    if (regex.test(value)) {
      matched.push(source);
    }
    regex.lastIndex = 0;
  }

  if (matched.length > 0) {
    return { matched: true, pattern: matched[0], patterns: matched, count: matched.length };
  }
  return { matched: false, patterns: [], count: 0 };
}
