import type { CompiledPatternSet } from "../patterns/loader.js";
// src/checkers/search-query.ts
import type { ContentCheckResult } from "../types.js";
import { scanContent } from "./content.js";

/**
 * Check a search query for leaked secrets, PII, or infrastructure details.
 * Uses websearch-leak-patterns.txt.
 *
 * Reuses scanContent — semantically identical, different pattern set.
 */
export function checkSearchQuery(
  query: string,
  patternSet: CompiledPatternSet,
): ContentCheckResult {
  return scanContent(query, patternSet);
}
