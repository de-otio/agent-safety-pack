# Remote APIs

## Overview

URL checking has three tiers: the static blocklist (`patterns/webfetch-domain-blocklist.txt`), local threat feeds (`feeds/`), and remote API checks. Remote APIs are the third tier — they query external services in real-time for each URL. They are disabled by default because they send every checked URL to the service provider (privacy cost). See `doc/analysis/external-url-analysis.md` for the full architecture.

Three services are supported:

1. **URLhaus API** (abuse.ch) -- primary recommendation
2. **Google Safe Browsing** (Google) -- broader coverage, requires API key
3. **Spamhaus DBL** (Spamhaus) -- domain-level DNS check

## Common Interface

All remote API modules implement the same internal interface:

```typescript
interface RemoteApiResult {
  source: string;          // e.g. "api:urlhaus"
  threatType: string;      // e.g. "malware_download", "SOCIAL_ENGINEERING"
  detail: string;          // human-readable detail
  reason: string;          // full human-readable reason string
}

interface RemoteApiClient {
  check(url: string, domain: string): Promise<RemoteApiResult | null>;
}
```

Returns `null` if the URL is clean or if the check failed (timeout, network error, malformed response). Failures are silent -- the caller proceeds as if the URL is clean.

## URLhaus API

**Source file:** `src/remote/urlhaus.ts`

**Endpoint:** `POST https://urlhaus-api.abuse.ch/v1/url/`

**Request:**
```
Content-Type: application/x-www-form-urlencoded
Body: url=<URL-encoded URL>
```

**Response parsing:**
- `query_status === "no_results"` -> clean, return null
- `query_status === "ok"` or other non-empty status -> flagged
  - `threat` field: e.g. `"malware_download"`
  - `tags` array: joined as detail string

**Implementation:**
```typescript
async function checkUrlhaus(url: string, timeout: number): Promise<RemoteApiResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(url)}`,
      signal: controller.signal,
    });

    const data = await response.json();

    if (data.query_status === 'no_results' || data.query_status === 'error' || !data.query_status) {
      return null;
    }

    return {
      source: 'api:urlhaus',
      threatType: data.threat ?? 'unknown',
      detail: Array.isArray(data.tags) ? data.tags.join(', ') : '',
      reason: `URLhaus: ${data.threat ?? 'flagged'} (${Array.isArray(data.tags) ? data.tags.join(', ') : 'no tags'})`,
    };
  } catch {
    // Timeout, network error, parse error -- fail open
    return null;
  } finally {
    clearTimeout(timer);
  }
}
```

**Notes:**
- No API key required. No rate limits. Operated by a Swiss non-profit.
- Uses `fetch` (built into Node 18+) with `AbortController` for timeout.

## Google Safe Browsing

**Source file:** `src/remote/google-safe-browsing.ts`

**Endpoint:** `POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=<API_KEY>`

**Request:**
```json
{
  "client": { "clientId": "agent-safety-pack", "clientVersion": "1.0" },
  "threatInfo": {
    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [{ "url": "<URL>" }]
  }
}
```

**Response parsing:**
- Empty object `{}` -> clean, return null
- Contains `matches` array -> flagged
  - `matches[0].threatType`: e.g. `"MALWARE"`, `"SOCIAL_ENGINEERING"`
  - Map threat type to human-readable detail:
    - `MALWARE` -> "Known malware distribution site"
    - `SOCIAL_ENGINEERING` -> "Phishing or social engineering page"
    - `UNWANTED_SOFTWARE` -> "Distributes unwanted software"
    - `POTENTIALLY_HARMFUL_APPLICATION` -> "Distributes potentially harmful applications"

**Notes:**
- Requires a Google Cloud API key. Setup: GCP Console -> APIs & Services -> Enable "Safe Browsing API" -> Create Credentials.
- 10,000 requests/day free tier.
- Broadest coverage of the three services (phishing, social engineering, unwanted software, not just malware).

**Security: API key must not appear in process arguments.** The endpoint URL contains the API key as a query parameter (`?key=...`). This URL must be constructed and used entirely within the library's in-process `fetch()` call — never passed as a command-line argument, shell variable, or subprocess argument. If the key were passed as a CLI argument, it would appear in `ps aux` output and be visible to any user on the system. The implementation reads the key from config or environment variable and builds the URL string inside the function scope, never exposing it to the process argument list.

## Spamhaus DBL

**Source file:** `src/remote/spamhaus-dbl.ts`

**Mechanism:** DNS lookup. Query `<domain>.dbl.spamhaus.org` for an A record.
- NXDOMAIN (no result) -> clean
- Any A record (e.g. `127.0.1.2`) -> domain is listed

**Implementation:**
```typescript
import { promises as dns } from 'node:dns';

async function checkSpamhausDbl(
  domain: string,
  timeout: number
): Promise<RemoteApiResult | null> {
  try {
    const results = await Promise.race([
      dns.resolve4(`${domain}.dbl.spamhaus.org`),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), timeout)
      ),
    ]);

    if (results && results.length > 0) {
      return {
        source: 'api:spamhaus-dbl',
        threatType: 'Spamhaus DBL listing',
        detail: results.join(', '),
        reason: `Domain listed in Spamhaus DBL: ${results.join(', ')}`,
      };
    }

    return null;
  } catch {
    // NXDOMAIN (clean), timeout, or network error -- all return null
    return null;
  }
}
```

**Notes:**
- No API key, no account. Free for non-commercial, low-volume use.
- Only checks domains, not full URLs. The domain is extracted from the URL before calling this.
- ~50ms per lookup -- fastest of the three services.
- Uses `node:dns` for DNS resolution.

## Privacy Considerations

As documented in `doc/analysis/external-url-analysis.md`:

- Remote APIs see every URL the agent checks. This reveals what documentation the user is reading, what errors they are debugging, what APIs they are integrating with.
- URLhaus has no authentication -- no user tracking, but also no privacy policy the user can enforce.
- Google Safe Browsing states it does not retain URLs, but this is a policy commitment, not a technical guarantee.
- Local threat feeds have zero privacy cost and are the recommended default.

The library defaults to all remote APIs disabled. Users opt in explicitly.

## Error Handling Summary

| Condition | Behavior |
|-----------|----------|
| Network timeout | Return null (fail open) |
| Connection refused | Return null (fail open) |
| HTTP 4xx/5xx | Return null (fail open) |
| Malformed JSON response | Return null (fail open) |
| DNS resolution failure (Spamhaus) | Return null (fail open) |
| Invalid API key (GSB) | Return null (fail open) |

Remote APIs are supplementary. A failure in any remote API does not prevent the URL from being allowed. The deterministic layers (blocklist + local feeds) are the real defense.
