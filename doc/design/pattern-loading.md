# Pattern Loading

## Overview

The `patterns/` directory contains six `.txt` files with a combined ~550 active regex patterns. The library loads these files at initialization, compiles each pattern to a JavaScript `RegExp`, and caches the compiled patterns for the lifetime of the `SafetyChecker` instance.

## Pattern File Format

All pattern files follow the same format:

- One extended regex per line
- Lines starting with `#` are comments
- Blank lines are ignored
- No trailing whitespace handling needed (patterns are trimmed)

The `sensitive-paths.txt` file has one additional convention: the marker line `# === ASK ===` separates the deny section (above) from the ask section (below). This is described in detail below.

## Compilation

```typescript
interface CompiledPattern {
  /** The original pattern string from the file. */
  source: string;
  /** The compiled RegExp. */
  regex: RegExp;
}

interface CompiledPatternSet {
  /** The file this set was loaded from (basename, e.g. "bash-deny"). */
  name: string;
  /** All compiled patterns. */
  patterns: CompiledPattern[];
}
```

Each pattern string is compiled to a `RegExp` using the `new RegExp(pattern, flags)` constructor. The flags depend on the pattern file:

| File | RegExp Flags | Rationale |
|------|-------------|-----------|
| `bash-deny.txt` | `i` | Case-insensitive to prevent uppercase bypass (e.g. `RM -RF /`, `EVAL $PAYLOAD`) |
| `webfetch-domain-blocklist.txt` | `i` | URLs and domains are case-insensitive |
| `secrets-patterns.txt` | `im` | Case-insensitive; multiline for `^`/`$` anchored patterns |
| `injection-patterns.txt` | `im` | Case-insensitive; multiline for content scanning |
| `websearch-leak-patterns.txt` | `im` | Case-insensitive; multiline for content scanning |
| `sensitive-paths.txt` | (none) | File paths are case-sensitive on Linux/macOS. On Windows, consider adding `i` flag. |

**Handling `(?i)` prefixes.** Some individual patterns contain inline `(?i)` flags. For simplicity and backward compatibility with Node 18/20, the library strips `(?i)` prefixes from patterns and instead applies the `i` flag to the entire `RegExp` when the pattern file is documented as case-insensitive. This is safe because all patterns within a given file are matched with the same case sensitivity.

## The Pattern Loader

```typescript
// patterns/loader.ts

interface LoadOptions {
  /** RegExp flags to apply to all patterns in this file. */
  flags?: string;
}

function loadPatternFile(filePath: string, options?: LoadOptions): CompiledPatternSet;
function loadPatternFileAsync(filePath: string, options?: LoadOptions): Promise<CompiledPatternSet>;
```

**Algorithm:**

1. Read the file contents as UTF-8 text.
2. Split on newlines.
3. For each line:
   - Trim whitespace.
   - Skip if empty or starts with `#`.
   - Strip leading `(?i)` if present (handled by file-level flags).
   - Compile to `RegExp` with the specified flags.
   - If compilation fails (invalid regex), log a warning and skip the pattern. Do not throw -- a single bad pattern should not prevent the rest from loading.
4. Return a `CompiledPatternSet`.

**Error handling for invalid patterns:** The pattern files use POSIX extended regex syntax, which is largely compatible with JavaScript `RegExp` but edge cases may exist. The loader logs a warning for each pattern that fails to compile, including the file name, line number, and error message. A single bad pattern does not prevent the rest from loading.

## The Pattern Matcher

```typescript
// patterns/matcher.ts

interface MatchResult {
  matched: boolean;
  /** The pattern string that matched. */
  pattern?: string;
}

/** Test a single string against a pattern set. Return on first match. */
function matchFirst(value: string, patternSet: CompiledPatternSet): MatchResult;

/** Test a single string against a pattern set. Return ALL matches. */
function matchAll(value: string, patternSet: CompiledPatternSet): MatchResult & {
  patterns: string[];
  count: number;
};
```

`matchFirst` is used by `checkCommand`, `checkUrl` (blocklist tier), and `checkSearchQuery` -- these need a single yes/no answer with the first matching pattern.

`matchAll` is used by `checkContentSecrets` and `checkContentInjection` -- these need to report every matching pattern in the content, not just the first.

## Sensitive Paths: Deny/Ask Sections

`sensitive-paths.txt` is unique among the pattern files because it has two sections separated by a `# === ASK ===` marker. Patterns above the marker are "deny" (hard block), patterns below are "ask" (escalate to user).

```typescript
// patterns/sensitive-paths.ts

interface SensitivePathSet {
  deny: CompiledPatternSet;
  ask: CompiledPatternSet;
}

function loadSensitivePaths(filePath: string): SensitivePathSet;
```

**Algorithm:**

1. Read the file.
2. Split on newlines.
3. Track a `section` variable, starting as `"deny"`.
4. When the line matches `# === ASK ===`, switch `section` to `"ask"`.
5. Compile patterns into the appropriate section.
6. Return both sets.

The `checkPath` method checks deny patterns first, then ask patterns. In strict mode, an ask match produces a deny decision.

## Caching and Performance

**Compile once, match many.** Pattern compilation happens once at `createSafetyChecker()` time. The compiled `RegExp` objects are reused for every subsequent check. For the ~550 patterns across all files, compilation takes <10ms on modern hardware.

**No runtime file I/O.** After initialization, the library never reads pattern files. All matching is in-memory. The `reload()` method re-reads files when explicitly called.

**Memory footprint.** Each compiled `RegExp` is a small object. The total memory for all ~550 patterns is negligible (well under 1MB).

**Matching performance.** A single pattern match (`regex.test(string)`) takes ~1 microsecond. Matching a URL against 130 blocklist patterns takes ~130 microseconds.
