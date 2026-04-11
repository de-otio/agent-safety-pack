# URL Checking

## The Three-Tier Pipeline

URL checking is the most complex check in the library. It mirrors the architecture in `doc/analysis/external-url-analysis.md`:

```
URL to check
  │
  ▼
Tier 1: Static blocklist patterns (instant, private, deterministic)
  │ match → return deny
  │ no match ↓
  ▼
Tier 2: Local threat feeds (instant, private, deterministic)
  │ match → return deny
  │ no match ↓
  ▼
Tier 3: Remote APIs (50-500ms, privacy cost, opt-in)
  │ match → return deny
  │ no match ↓
  ▼
Return allow
```

Each tier short-circuits on match. If Tier 1 matches, Tiers 2 and 3 are never consulted.

## Tier 1: Static Blocklist

Patterns from `patterns/webfetch-domain-blocklist.txt`, compiled to RegExp at initialization (case-insensitive).

The full URL is tested against each pattern. This catches:
- Domain-based blocks (e.g. `\bbit\.ly\b` matches `https://bit.ly/abc`)
- Scheme-based blocks (e.g. `^data:` matches `data:text/html,...`)
- IP-based blocks (e.g. `https?://\d+\.\d+\.\d+\.\d+` matches bare IP URLs)
- Path-based blocks (e.g. internal network patterns)

**Matching:** Uses `matchFirst(url, blocklistPatterns)` -- return on first match.

## Tier 2: Local Threat Feeds

Feed files in `feeds/*.txt`, loaded into `Set<string>` at initialization. Each feed is a separate Set.

The check is a literal string lookup (`Set.has(url)`). This is O(1) per feed, regardless of feed size.

**URL normalization:** `Set.has()` is an exact full-string match. Feed databases store URLs in canonical form; URLs arriving from the agent may include fragments (`#section`) or tracking query strings (`?ref=...`) that are absent in the feed entry. The library checks the original URL, the URL with trailing slash stripped, and the URL with fragment + query string + trailing slash stripped. See `doc/design/threat-feeds.md` for the normalization algorithm.

## Tier 3: Remote APIs

Optional, opt-in. Each API is an independent module. When multiple APIs are enabled, they are queried in order (not in parallel) to minimize unnecessary network calls -- if URLhaus returns a match, Google Safe Browsing is not queried.

**Query order:**
1. URLhaus API (if enabled)
2. Google Safe Browsing (if enabled)
3. Spamhaus DBL (if enabled)

**Short-circuit:** First match from any API terminates the pipeline and returns deny.

**Error handling:** Each API call is wrapped in a try/catch with a timeout. Network errors, timeouts, and malformed responses are treated as "no result" (the URL is not flagged). Remote APIs fail open -- they are supplementary.

**Timeout:** Each API call has an independent timeout (default 5000ms, configurable). The total worst-case latency when all three APIs are enabled and all time out is 15 seconds. Callers should be aware of this.

## The checkUrl Method

```typescript
async checkUrl(url: string): Promise<UrlCheckResult> {
  // Input validation
  if (!url || typeof url !== 'string') {
    return { decision: 'allow', url };
  }

  const domain = extractDomain(url);

  // Tier 1: Static blocklist
  const blocklistMatch = matchFirst(url, this.blocklistPatterns);
  if (blocklistMatch.matched) {
    return {
      decision: 'deny',
      url,
      tier: 'blocklist',
      matchedPattern: blocklistMatch.pattern,
      source: 'webfetch-domain-blocklist',
      reason: `URL matches blocklist pattern: ${blocklistMatch.pattern}`,
    };
  }

  // Tier 2: Local feeds
  if (this.config.localFeeds) {
    const feedMatch = this.checkFeeds(url);
    if (feedMatch) {
      return {
        decision: 'deny',
        url,
        tier: 'feed',
        feedName: feedMatch.feedName,
        source: `feed:${feedMatch.feedName}`,
        reason: `URL found in ${feedMatch.description}`,
      };
    }
  }

  // Tier 3: Remote APIs
  const apiResult = await this.checkRemoteApis(url, domain);
  if (apiResult) {
    return {
      decision: 'deny',
      url,
      tier: 'api',
      source: apiResult.source,
      threatType: apiResult.threatType,
      threatDetail: apiResult.detail,
      reason: apiResult.reason,
    };
  }

  return { decision: 'allow', url };
}
```

## Domain Extraction

Extracts the hostname from a URL:

```typescript
function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    // Fallback for malformed URLs: strip scheme and path manually.
    // SECURITY: must strip userinfo (user:pass@) before extracting the host,
    // or `user:pass@evil.com` would be parsed as host="user", not "evil.com".
    return url
      .replace(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//, '') // strip scheme
      .replace(/^[^@]*@/, '')                          // strip userinfo (user:pass@)
      .split('/')[0]                                   // strip path
      .split(':')[0]                                   // strip port
      .split('?')[0]                                   // strip query
      .split('#')[0];                                  // strip fragment
  }
}
```

The `URL` constructor handles edge cases (IPv6, ports, auth) correctly for well-formed URLs; it is the primary path. The fallback handles partial URLs and non-HTTP schemes, and must strip userinfo before splitting on `:` — otherwise a URL like `https://user:pass@evil.com/` would incorrectly extract `user` as the host instead of `evil.com`.
