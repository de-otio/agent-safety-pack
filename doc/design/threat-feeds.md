# Threat Feeds

## Overview

Local threat feeds are downloaded databases from URLhaus, PhishTank, and OpenPhish. They are stored as plain text files in `feeds/`, one URL per line. The library loads these files into `Set<string>` data structures for O(1) lookup.

This is Tier 2 of the URL check pipeline. Active by default, zero privacy cost -- the databases are checked locally with no per-URL network calls.

## Feed Files

| Feed | File | Source URL | Content |
|------|------|-----------|---------|
| URLhaus | `feeds/urlhaus.txt` | `https://urlhaus.abuse.ch/downloads/text_online/` | Active malware distribution URLs |
| PhishTank | `feeds/phishtank.txt` | `http://data.phishtank.com/data/online-valid.csv` | Verified phishing URLs |
| OpenPhish | `feeds/openphish.txt` | `https://openphish.com/feed.txt` | ML-detected phishing URLs |

Feed files are plain text, one URL per line. They can be downloaded from the source URLs above and placed in `feeds/`. The library does not download feeds -- it only reads what has been placed on disk. A feed update utility is provided (see below).

## Loading into Memory

```typescript
interface LoadedFeed {
  name: string;           // "urlhaus", "phishtank", "openphish"
  path: string;           // absolute path to the feed file
  entries: Set<string>;   // all URLs in the feed
  entryCount: number;     // entries.size
  modifiedAt: Date;       // file mtime
  ageSeconds: number;     // seconds since last modification
  stale: boolean;         // ageSeconds > 86400 (24 hours)
  description: string;    // human-readable description
}

interface LoadedFeeds {
  feeds: Map<string, LoadedFeed>;
  totalEntries: number;
}
```

**Algorithm:**

1. List `*.txt` files in `feedsDir`.
2. For each file:
   a. Read the file as UTF-8.
   b. Split on newlines.
   c. Trim each line, skip empty lines.
   d. Add each non-empty line to a `Set<string>`.
   e. Read the file's `mtime` from `fs.statSync`.
   f. Compute `ageSeconds = (Date.now() - mtime) / 1000`.
   g. Set `stale = ageSeconds > 86400`.
3. Map feed name to description:
   - `urlhaus` -> "URLhaus (abuse.ch) -- active malware distribution URLs"
   - `phishtank` -> "PhishTank (Cisco) -- verified phishing URLs"
   - `openphish` -> "OpenPhish -- ML-detected phishing URLs"

## O(1) Lookup

`Set.has(url)` is O(1) average case. This makes feed checking effectively instant regardless of feed size. A typical URLhaus feed has ~10,000-50,000 entries; PhishTank may have ~50,000-100,000. The combined memory for all three feeds as Sets of strings is 10-50MB -- acceptable for a server-side library.

## URL Normalization Before Lookup

Feed databases store URLs in a canonical form. A URL arriving from the agent may carry a fragment (`#section`) or query string (`?ref=...`) that is absent in the feed entry. A naive `Set.has(url)` would miss the match.

The library normalizes the URL before lookup by:
1. Stripping the fragment (`#...` and everything after)
2. Stripping the query string (`?...` and everything after)
3. Stripping a trailing slash (existing behavior)

All three normalized forms are checked: the original URL, the URL with only trailing slash stripped, and the URL with fragment+query+trailing slash stripped. This ensures a URL like `https://evil.example.com/malware.exe?track=123#start` matches a feed entry of `https://evil.example.com/malware.exe`.

## Checking a URL Against Feeds

```typescript
function normalizeForFeedLookup(url: string): string[] {
  const candidates = new Set<string>();
  candidates.add(url);
  // Strip trailing slash
  candidates.add(url.replace(/\/$/, ''));
  // Strip fragment and query string, then trailing slash
  const bare = url.replace(/[?#].*$/, '').replace(/\/$/, '');
  candidates.add(bare);
  return [...candidates];
}

function checkFeeds(
  url: string,
  feeds: Map<string, LoadedFeed>
): { feedName: string; description: string } | null {
  const candidates = normalizeForFeedLookup(url);
  for (const [name, feed] of feeds) {
    for (const candidate of candidates) {
      if (feed.entries.has(candidate)) {
        return { feedName: name, description: feed.description };
      }
    }
  }
  return null;
}
```

The check iterates over all loaded feeds. Since `Set.has` is O(1), the total time is O(feeds × candidates) = O(3 × 3) = O(1).

## Feed Health Status

The `feedStatus()` method reports on feed health:

```typescript
function getFeedStatus(feedsDir: string, feeds: Map<string, LoadedFeed>): FeedStatus {
  if (!existsSync(feedsDir)) {
    return { status: 'no-feeds-dir', feedCount: 0, staleFeedCount: 0, feeds: [] };
  }

  if (feeds.size === 0) {
    return { status: 'no-feeds', feedCount: 0, staleFeedCount: 0, feeds: [] };
  }

  const feedInfos: FeedInfo[] = [];
  let staleCount = 0;

  for (const [, feed] of feeds) {
    if (feed.stale) staleCount++;
    feedInfos.push({
      name: feed.name,
      path: feed.path,
      entryCount: feed.entryCount,
      ageSeconds: feed.ageSeconds,
      stale: feed.stale,
    });
  }

  return {
    status: staleCount > 0 ? 'stale' : 'ok',
    feedCount: feeds.size,
    staleFeedCount: staleCount,
    feeds: feedInfos,
  };
}
```

## Refresh

Feeds are not refreshed automatically. The `reload()` method re-reads all feed files from disk. The expected workflow:

1. A cron job or scheduled task downloads fresh feeds periodically.
2. The application calls `checker.reload()` after the update, or creates a new `SafetyChecker` instance.

Alternatively, the application can periodically call `checker.feedStatus()` and trigger a reload when feeds are stale.

## Feed Update Requirements

The feed update utility (which downloads fresh feed files) must follow these requirements to prevent a compromised or unavailable upstream from replacing a good feed with bad data:

1. **HTTPS only.** All download requests must use `https://`. Plain HTTP must be rejected regardless of the source URL. If a feed source URL in the table above ever changes to HTTP, the downloader must fail rather than follow it.

2. **Fail on HTTP errors.** If the server returns a non-2xx status code, the existing feed file must not be replaced. An HTTP 429, 503, or error page body is not a valid feed.

3. **Minimum entry count validation.** Before replacing the live feed file, validate that the downloaded content has a minimum number of entries (suggested: 100 lines). A feed that downloads as an empty file, a single error message, or a truncated partial response must be rejected. The specific threshold should be configurable per feed.

4. **Atomic replacement.** Write the new feed to a temp file in the same directory, validate it, then rename it over the live file. This prevents a partial download from corrupting the live feed.

5. **Preserve the live feed on failure.** If validation fails or the download errors, the existing feed file must remain untouched. The update utility should log the failure and exit non-zero.

These requirements ensure that a network error, a rate-limit response, or a supply-chain compromise of the feed source degrades gracefully (stale feed, still protecting) rather than catastrophically (empty feed, no protection).

## Missing Feeds

When `feedsDir` does not exist or contains no `.txt` files, the library operates without feed checking. This is not an error -- feeds are supplementary. The `feedStatus()` method reports the condition so callers can log a warning.
