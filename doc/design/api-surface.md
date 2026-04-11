# API Surface

This is the public contract of the library. Everything in this file is part of the published API and subject to semver.

## Factory Function

```typescript
import { createSafetyChecker } from '@de-otio/agent-safety-pack';

const checker = createSafetyChecker({
  // All options are optional. Defaults are shown.
  patternsDir: undefined,    // auto-resolved to bundled patterns/
  feedsDir: undefined,       // auto-resolved to feeds/ next to patterns/
  strict: false,             // true = all "ask" becomes "deny"
  localFeeds: true,          // check local threat feed files
  remoteApis: {
    urlhaus: false,          // set true to enable URLhaus API
    googleSafeBrowsing: undefined, // set to API key string to enable
    spamhausDbl: false,      // set true to enable DNS blocklist
  },
  timeouts: {
    remoteApi: 5000,         // ms, per remote API call
  },
});
```

### Async Variant

```typescript
const checker = await createSafetyCheckerAsync(config);
```

Same configuration, but pattern and feed loading is non-blocking. Useful in environments where synchronous file I/O is discouraged.

## Configuration Type

```typescript
interface SafetyCheckerConfig {
  /**
   * Path to the directory containing pattern .txt files.
   * Defaults to the bundled patterns/ directory shipped with the package.
   * Override to use custom patterns.
   */
  patternsDir?: string;

  /**
   * Path to the directory containing downloaded threat feed .txt files.
   * Defaults to feeds/ adjacent to patternsDir.
   * Feed files are plain text, one URL per line.
   */
  feedsDir?: string;

  /**
   * Strict mode for autonomous agents. When true, all "ask" decisions
   * become "deny". There is no human to ask.
   * Defaults to false. Can also be set via AGENT_SAFETY_MODE=strict env var.
   */
  strict?: boolean;

  /**
   * Whether to check URLs against local threat feed files.
   * Defaults to true. Set false to disable (not recommended).
   * Can also be set via AGENT_SAFETY_LOCAL_FEEDS=0 env var.
   */
  localFeeds?: boolean;

  /**
   * Remote API configuration. All disabled by default (privacy tradeoff).
   */
  remoteApis?: {
    /** Enable URLhaus API checks. No key required. */
    urlhaus?: boolean;
    /** Google Safe Browsing API key. Set to enable. */
    googleSafeBrowsing?: string;
    /** Enable Spamhaus DBL DNS checks. No key required. */
    spamhausDbl?: boolean;
  };

  /**
   * Timeout configuration in milliseconds.
   */
  timeouts?: {
    /** Timeout for each remote API call. Default: 5000ms. */
    remoteApi?: number;
  };
}
```

## SafetyChecker Interface

```typescript
interface SafetyChecker {
  /**
   * Check a command against bash deny patterns.
   * Synchronous -- pattern matching only.
   */
  checkCommand(command: string): CheckResult;

  /**
   * Check a URL against blocklist patterns, local feeds, and remote APIs.
   * Async -- may make network calls if remote APIs are enabled.
   * Tiers are checked in order; first match short-circuits.
   */
  checkUrl(url: string): Promise<UrlCheckResult>;

  /**
   * Check a file path against sensitive path patterns.
   * Synchronous -- pattern matching only.
   * Returns deny/ask/allow based on which section matched.
   *
   * IMPORTANT: The caller must pass an absolute path. Relative paths (e.g. `.env`)
   * will not match patterns that anchor on the leading `/` (e.g. `^/etc/`).
   * Resolve relative paths before calling: `path.resolve(filePath)`.
   */
  checkPath(filePath: string): PathCheckResult;

  /**
   * Scan content for secrets patterns.
   * Synchronous -- pattern matching only.
   * Returns all matching patterns (not just the first).
   */
  checkContentSecrets(content: string): ContentCheckResult;

  /**
   * Scan content for prompt injection patterns.
   * Synchronous -- pattern matching only.
   * Returns all matching patterns (not just the first).
   */
  checkContentInjection(content: string): ContentCheckResult;

  /**
   * Check a search query for leaked secrets, PII, or infrastructure details.
   * Synchronous -- pattern matching only.
   */
  checkSearchQuery(query: string): ContentCheckResult;

  /**
   * Get the current health status of local threat feeds.
   * Returns feed count, staleness, and individual feed info.
   */
  feedStatus(): FeedStatus;

  /**
   * Reload pattern files and feeds from disk.
   * Call this after updating patterns or refreshing threat feeds.
   */
  reload(): void;

  /**
   * Async variant of reload().
   */
  reloadAsync(): Promise<void>;

  /**
   * The resolved configuration (with defaults applied).
   */
  readonly config: Readonly<ResolvedConfig>;
}
```

## Result Types

### CheckResult (base)

```typescript
type CheckDecision = 'allow' | 'deny' | 'ask';

interface CheckResult {
  /** The decision: allow, deny, or ask. */
  decision: CheckDecision;

  /**
   * The regex pattern that matched, if any.
   * Undefined when decision is "allow".
   */
  matchedPattern?: string;

  /**
   * Which source produced the match.
   * Examples: "bash-deny", "webfetch-domain-blocklist", "sensitive-paths",
   * "feed:urlhaus", "api:google-safe-browsing"
   */
  source?: string;

  /**
   * Human-readable explanation of why this was flagged.
   * Suitable for showing to a user or logging.
   */
  reason?: string;
}
```

### UrlCheckResult

```typescript
interface UrlCheckResult extends CheckResult {
  /** The URL that was checked. */
  url: string;

  /** Which tier produced the match: "blocklist" | "feed" | "api" | undefined */
  tier?: 'blocklist' | 'feed' | 'api';

  /** For feed matches: the feed name (e.g. "urlhaus", "phishtank"). */
  feedName?: string;

  /** For API matches: threat type from the API (e.g. "malware_download"). */
  threatType?: string;

  /** For API matches: additional detail from the API. */
  threatDetail?: string;
}
```

### PathCheckResult

```typescript
interface PathCheckResult extends CheckResult {
  /** The file path that was checked. */
  filePath: string;

  /**
   * Which section of sensitive-paths.txt matched: "deny" or "ask".
   * In strict mode, "ask" sections produce decision: "deny".
   * Undefined when decision is "allow".
   */
  section?: 'deny' | 'ask';
}
```

### ContentCheckResult

```typescript
interface ContentCheckResult extends CheckResult {
  /**
   * All patterns that matched, not just the first.
   * Content scanning finds multiple issues -- callers need the full list.
   */
  matchedPatterns: string[];

  /** Number of patterns that matched. */
  matchCount: number;
}
```

### FeedStatus

```typescript
interface FeedInfo {
  name: string;
  path: string;
  /** Number of entries in the feed. */
  entryCount: number;
  /** Age of the feed file in seconds. */
  ageSeconds: number;
  /** Whether the feed is considered stale (older than 24 hours). */
  stale: boolean;
}

interface FeedStatus {
  /** Overall status. */
  status: 'ok' | 'stale' | 'no-feeds' | 'no-feeds-dir';
  /** Number of loaded feeds. */
  feedCount: number;
  /** Number of stale feeds. */
  staleFeedCount: number;
  /** Per-feed details. */
  feeds: FeedInfo[];
}
```

## Convenience Exports

```typescript
// Re-exported from index.ts for convenience:
export { createSafetyChecker, createSafetyCheckerAsync } from './factory';
export type {
  SafetyCheckerConfig,
  SafetyChecker,
  CheckResult,
  CheckDecision,
  UrlCheckResult,
  PathCheckResult,
  ContentCheckResult,
  FeedStatus,
  FeedInfo,
} from './types';
```

## Usage Examples

### Basic Usage (Interactive Agent)

```typescript
import { createSafetyChecker } from '@de-otio/agent-safety-pack';

const checker = createSafetyChecker();

// Pre-execution: check a command
const cmdResult = checker.checkCommand('rm -rf /');
if (cmdResult.decision !== 'allow') {
  console.error(`Blocked: ${cmdResult.reason}`);
  // do not execute the command
}

// Pre-execution: check a URL
const urlResult = await checker.checkUrl('https://bit.ly/abc123');
if (urlResult.decision === 'deny') {
  console.error(`URL blocked: ${urlResult.reason}`);
} else if (urlResult.decision === 'ask') {
  // show warning to user, let them decide
}

// Post-execution: scan fetched content
const fetchedHtml = await fetch(url).then(r => r.text());
const injectionResult = checker.checkContentInjection(fetchedHtml);
if (injectionResult.decision !== 'allow') {
  console.warn(`Injection detected: ${injectionResult.matchCount} patterns`);
}
```

### Strict Mode (Autonomous Agent)

```typescript
const checker = createSafetyChecker({ strict: true });

// "ask" results are now "deny" -- there is no human to ask
const pathResult = checker.checkPath('.github/workflows/deploy.yml');
// pathResult.decision === 'deny' (would be 'ask' without strict mode)
```

### With Remote APIs

```typescript
const checker = createSafetyChecker({
  remoteApis: {
    urlhaus: true,
    googleSafeBrowsing: process.env.AGENT_SAFETY_GSB_KEY,
    spamhausDbl: true,
  },
});

const result = await checker.checkUrl('https://suspicious-site.example.com/payload');
// Checks: blocklist -> local feeds -> URLhaus API -> Google Safe Browsing -> Spamhaus DBL
```

### Custom Patterns Directory

```typescript
const checker = createSafetyChecker({
  patternsDir: '/path/to/my/custom/patterns',
});
```

## Environment Variable Overrides

The library reads these environment variables:

| Variable | Effect |
|----------|--------|
| `AGENT_SAFETY_MODE=strict` | Sets `strict: true` (overridden by explicit config) |
| `AGENT_SAFETY_LOCAL_FEEDS=0` | Sets `localFeeds: false` |
| `AGENT_SAFETY_URLHAUS=1` | Sets `remoteApis.urlhaus: true` |
| `AGENT_SAFETY_GSB_KEY=<key>` | Sets `remoteApis.googleSafeBrowsing` |
| `AGENT_SAFETY_DNSBL=1` | Sets `remoteApis.spamhausDbl: true` |

Explicit config values take precedence over environment variables. Environment variables take precedence over defaults. This allows the same code to behave differently in interactive vs. autonomous deployments without code changes.
