import { matchFirst } from "../patterns/matcher.js";
import type { SensitivePathSet } from "../patterns/sensitive-paths.js";
import type { PathCheckResult } from "../types.js";

/**
 * Check a file path against sensitive path patterns.
 *
 * IMPORTANT: The caller must pass an absolute path.
 * Relative paths (e.g. '.env') will not match patterns anchored with '^/'
 * The factory's checkPath method resolves relative paths before calling this.
 *
 * Returns:
 *   - 'deny' if path matches the deny section
 *   - 'ask' if path matches the ask section (or 'deny' if strict mode)
 *   - 'allow' if no match
 *
 * The 'section' field is always set to the original section, even when
 * strict mode converts 'ask' to 'deny'. This lets callers distinguish
 * "hard deny" from "strict-mode converted ask".
 */
export function checkPath(
  filePath: string,
  paths: SensitivePathSet,
  strict: boolean,
): PathCheckResult {
  if (!filePath || typeof filePath !== "string") {
    return { decision: "allow", filePath: filePath ?? "" };
  }

  // Check deny section first
  const denyMatch = matchFirst(filePath, paths.deny);
  if (denyMatch.matched) {
    return {
      decision: "deny",
      filePath,
      section: "deny",
      matchedPattern: denyMatch.pattern,
      source: "sensitive-paths",
      reason: `Path matches sensitive pattern (deny): ${denyMatch.pattern}`,
    };
  }

  // Check ask section
  const askMatch = matchFirst(filePath, paths.ask);
  if (askMatch.matched) {
    if (strict) {
      return {
        decision: "deny",
        filePath,
        section: "ask",
        matchedPattern: askMatch.pattern,
        source: "sensitive-paths",
        reason: `Path matches sensitive pattern (strict mode — ask converted to deny): ${askMatch.pattern}`,
      };
    }
    return {
      decision: "ask",
      filePath,
      section: "ask",
      matchedPattern: askMatch.pattern,
      source: "sensitive-paths",
      reason: `Path matches sensitive pattern (user review recommended): ${askMatch.pattern}`,
    };
  }

  return { decision: "allow", filePath };
}
