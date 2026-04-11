# Architecture

## Module Structure

```
src/
  index.ts                  Public API entry point (re-exports)
  factory.ts                createSafetyChecker() factory function
  types.ts                  All TypeScript interfaces and types
  config.ts                 Configuration validation and defaults
  patterns/
    loader.ts               Load .txt files, compile to RegExp, cache
    matcher.ts              Match a string against a compiled pattern set
    sensitive-paths.ts      Special handling for deny/ask sections
  checkers/
    command.ts              Check commands against bash-deny.txt
    url.ts                  Three-tier URL check pipeline
    path.ts                 Check file paths against sensitive-paths.txt
    content.ts              Scan content for secrets or injection patterns
    search-query.ts         Check search queries for leaked secrets/PII
  feeds/
    loader.ts               Load local threat feed files into Sets
    status.ts               Feed health/staleness checks
  remote/
    urlhaus.ts              URLhaus API client
    google-safe-browsing.ts Google Safe Browsing API client
    spamhaus-dbl.ts         Spamhaus DNS blocklist client
  utils/
    url.ts                  URL parsing (extract domain, etc.)
```

## Dependency Graph

```
index.ts
  └── factory.ts
        ├── config.ts
        ├── types.ts
        ├── patterns/loader.ts
        │     └── patterns/matcher.ts
        ├── patterns/sensitive-paths.ts
        │     └── patterns/matcher.ts
        ├── checkers/command.ts
        │     └── patterns/matcher.ts
        ├── checkers/url.ts
        │     ├── patterns/matcher.ts
        │     ├── feeds/loader.ts
        │     ├── remote/urlhaus.ts
        │     ├── remote/google-safe-browsing.ts
        │     └── remote/spamhaus-dbl.ts
        ├── checkers/path.ts
        │     └── patterns/sensitive-paths.ts
        ├── checkers/content.ts
        │     └── patterns/matcher.ts
        └── checkers/search-query.ts
              └── patterns/matcher.ts
```

All arrows point downward. There are no circular dependencies. Each checker depends on the pattern subsystem but not on other checkers. Remote API modules have no internal dependencies -- they are standalone HTTP/DNS clients.

## Initialization Flow

```
1. User calls createSafetyChecker(config?)
     │
2. Validate and merge config with defaults
     │
3. Resolve patternsDir path
     │  (default: ../patterns/ relative to package root)
     │
4. Load and compile pattern files (synchronous, once)
     │  ├── bash-deny.txt          → CompiledPatternSet
     │  ├── webfetch-domain-blocklist.txt → CompiledPatternSet (case-insensitive)
     │  ├── secrets-patterns.txt   → CompiledPatternSet (case-insensitive)
     │  ├── injection-patterns.txt → CompiledPatternSet (case-insensitive)
     │  ├── websearch-leak-patterns.txt → CompiledPatternSet (case-insensitive)
     │  └── sensitive-paths.txt    → SensitivePathSet (with deny/ask sections)
     │
5. If localFeeds enabled and feedsDir exists:
     │  Load feed files into Set<string> (one Set per feed file)
     │
6. Return SafetyChecker instance with bound methods
```

Initialization is synchronous by default for pattern files (they are small, ~10-50KB total). Feed loading is also synchronous by default (feeds can be larger, but are still in-memory text files). An async `createSafetyCheckerAsync()` variant is provided for environments that prefer non-blocking initialization.

## Runtime Flow (Example: URL Check)

```
checker.checkUrl("https://bit.ly/abc123")
  │
  ├── Tier 1: matcher.matchAny(url, blocklistPatterns)
  │     └── Match found → return { decision: "deny", source: "blocklist", ... }
  │
  ├── Tier 2: feeds.has(url) for each loaded feed Set
  │     └── Match found → return { decision: "deny", source: "feed:urlhaus", ... }
  │
  ├── Tier 3 (if enabled): remote API calls (sequential, short-circuit)
  │     ├── urlhaus.check(url)
  │     ├── gsb.check(url)
  │     └── dnsbl.check(domain)
  │     └── Match found → return { decision: "deny", source: "api:urlhaus", ... }
  │
  └── No match → return { decision: "allow" }
```

Short-circuit: each tier returns immediately on first match. Later tiers are not consulted. Remote API calls respect configured timeouts and fail open (network error = allow, not deny).

## Key Design Decisions

**Synchronous pattern matching, async remote APIs.** Pattern matching is CPU-bound and fast (<1ms for 100 patterns). Remote APIs are I/O-bound (50-500ms). The `checkUrl()` method is async because it may call remote APIs. The `checkCommand()`, `checkPath()`, and `checkContent()` methods are synchronous because they only do pattern matching. This matches the reality of what each check does.

**One SafetyChecker instance per configuration.** The factory function returns an object with all patterns pre-compiled. Creating a new instance per request would waste time recompiling patterns. The typical usage is: create one instance at application startup, use it for all checks.

**Pattern files are not watched.** If patterns change on disk, the caller must create a new `SafetyChecker` instance or call `reload()`. File watching adds complexity and is unnecessary for the primary use case (patterns change at deploy time, not at runtime).

**Feeds are loaded eagerly, not lazily.** Feed files can be 1-10MB. Loading them into a `Set<string>` at initialization means O(1) lookups during checks. The memory cost is acceptable for a server-side library.
