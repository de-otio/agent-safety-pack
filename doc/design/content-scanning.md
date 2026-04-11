# Content Scanning

## Overview

Content scanning checks text (command output, fetched HTML, written file content, search queries) against pattern files. Unlike URL and command checks which return on the first match, content scanning reports *all* matching patterns -- callers need the complete picture.

The library exposes three content scanning methods:
- `checkContentSecrets(content)` -- scans against `secrets-patterns.txt`
- `checkContentInjection(content)` -- scans against `injection-patterns.txt`
- `checkSearchQuery(query)` -- scans against `websearch-leak-patterns.txt`

## Matching Strategy

The implementation tests the full content string against every compiled pattern, collecting all matches.

```typescript
function scanContent(
  content: string,
  patternSet: CompiledPatternSet
): ContentCheckResult {
  if (!content) {
    return { decision: 'allow', matchedPatterns: [], matchCount: 0 };
  }

  const matched: string[] = [];

  for (const { source, regex } of patternSet.patterns) {
    if (regex.test(content)) {
      matched.push(source);
    }
    // Reset lastIndex in case the regex has the global flag
    regex.lastIndex = 0;
  }

  if (matched.length > 0) {
    return {
      decision: 'deny',
      matchedPatterns: matched,
      matchCount: matched.length,
      source: patternSet.name,
      reason: `${matched.length} pattern(s) matched`,
    };
  }

  return { decision: 'allow', matchedPatterns: [], matchCount: 0 };
}
```

## Full-Content vs Line-by-Line Matching

JavaScript's `RegExp.test()` tests against the entire string by default. Patterns with `^` and `$` anchors are meant to match individual lines (e.g. `^[A-Z_]{3,50}=[a-zA-Z0-9/+=_-]{20,}$` from `secrets-patterns.txt` targets lines in `.env` files).

**Solution:** Apply the `m` (multiline) flag when compiling content-scanning patterns. This makes `^` and `$` match line boundaries.

| File | Flags |
|------|-------|
| `secrets-patterns.txt` | `im` (case-insensitive + multiline) |
| `injection-patterns.txt` | `im` (case-insensitive + multiline) |
| `websearch-leak-patterns.txt` | `im` (case-insensitive + multiline) |

The `m` flag is appropriate for all content scanning files because they were designed for `grep`, which inherently operates line-by-line.

## Integration with Check Pipeline

Content scanning is post-fetch / post-execution. The typical flow:

```
Agent fetches URL  → fetch succeeds → checkContentInjection(responseBody)
Agent runs command → command succeeds → checkContentSecrets(stdout)
Agent writes file  → write succeeds → checkContentSecrets(fileContent)
Agent searches     → pre-search     → checkSearchQuery(query)
```

The content scanning methods are synchronous (in-memory pattern matching only). They can be called inline without awaiting.

## Performance Considerations

**Content size:** Fetched web pages can be large (100KB-1MB). Testing ~100 regex patterns against 1MB of text takes 10-100ms depending on pattern complexity. This is acceptable for post-fetch scanning where the fetch itself took 100ms-5s.

**Short-circuit vs complete scan:** Unlike command/URL checks (which return on first match), content scanning finds all matches. This is intentional -- the caller needs to know the full extent of the problem. A page with 3 injection patterns is more concerning than a page with 1, and the specific patterns inform the response.

**RegExp state:** The patterns are compiled without the `g` (global) flag. `RegExp.test()` without `g` does not update `lastIndex`, so patterns are safe for reuse across calls without resetting. If any pattern is inadvertently compiled with `g`, the `lastIndex = 0` reset in the scan loop handles it safely.

## Search Query Scanning

`checkSearchQuery()` uses the same `scanContent()` function with `websearch-leak-patterns.txt`. The semantics are different from secrets/injection scanning:

- The input is short (a search query, not a page of HTML)
- A single match is sufficient to flag the query
- The dedicated `websearch-leak-patterns.txt` file targets secrets, PII, and infrastructure details that should not appear in search queries

The method returns a `ContentCheckResult` for consistency, but in practice the `matchCount` is usually 0 or 1 for search queries.
