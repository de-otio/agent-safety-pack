# External URL Safety Analysis

The static blocklist in `patterns/webfetch-domain-blocklist.txt` catches known-dangerous URL categories (shorteners, paste sites, internal networks). Threat intelligence adds coverage for specific URLs that have been identified as actively hosting malware or phishing — threats that a static category list cannot know about.

This coverage comes in two forms:

- **Local threat feeds** (active by default, zero privacy cost) — downloaded databases from URLhaus, PhishTank, and OpenPhish, checked locally with no per-URL network calls. The library provides a `reload()` method; a companion CLI or cron job populates `feeds/` on a schedule.
- **Remote API checks** (opt-in, privacy tradeoff) — real-time queries to URLhaus API, Google Safe Browsing, or Spamhaus DBL. These see every URL Claude attempts to fetch.

Both are supplements to the deterministic pattern layer, not replacements. The static blocklist runs first, costs nothing, sends nothing externally, and cannot be bypassed.

## Remote API Services

For users who opt into remote checks, the pre-fetch hook must respond in under 5 seconds. This eliminates services that perform live page analysis (urlscan.io, Cloudflare Radar, VirusTotal on cache miss). Four services are fast enough:

### Primary: URLhaus (abuse.ch)

| Service | Latency | Free Limit | Auth Required | Privacy Cost | Coverage |
|---------|---------|------------|---------------|-------------|----------|
| **URLhaus (abuse.ch)** | 100-300ms | Unlimited | None | URL sent to abuse.ch | Malware distribution URLs |

**URLhaus is the default recommendation.** No API key, no account creation, no rate limits, no billing surprises. Operated by abuse.ch, a Swiss non-profit security research project. Zero setup friction means users can enable it with a single env var (`AGENT_SAFETY_URLHAUS=1`) and start getting protection immediately.

### Fallback: Google Safe Browsing

| Service | Latency | Free Limit | Auth Required | Privacy Cost | Coverage |
|---------|---------|------------|---------------|-------------|----------|
| **Google Safe Browsing** | 50-200ms | 10,000/day | API key (GCP Console) | Full URL sent to Google | Malware, phishing, social engineering, unwanted software |

**Google Safe Browsing has broader coverage** (phishing, social engineering, unwanted software — not just malware) but requires a Google Cloud project, enabling the API, and generating a key. It's the same database Chrome and Firefox use. For organizations already in the GCP ecosystem, the setup cost is low. For everyone else, URLhaus gets you most of the value with none of the friction.

### Tier B: Supplementary

| Service | Latency | Free Limit | Auth Required | Privacy Cost | Coverage |
|---------|---------|------------|---------------|-------------|----------|
| **PhishTank** | 100-500ms | Moderate | Optional API key | URL sent to Cisco | Phishing only |
| **DNS Blocklists** (Spamhaus DBL, SURBL) | ~50ms | Non-commercial use | None | Domain sent via DNS | Spam, malware, phishing domains |

### Not Recommended for Synchronous Use

| Service | Why Not |
|---------|---------|
| **VirusTotal** | 4 req/min free limit; cache miss = 15-60s; free-tier queries are **public** |
| **urlscan.io** | Live page scan takes 10-30s |
| **Cloudflare Radar** | Live scan, 10-30s |
| **IPQS** | 200/day limit too low for active development |

## Privacy Considerations

**Local threat feeds have zero privacy cost.** The databases are downloaded in bulk and checked locally. No per-URL network call is made during checks. The feed providers see a single download request, not what you're checking against it.

**Remote API checks send every checked URL to the service.** This means:

1. **The service sees every URL Claude attempts to fetch.** This includes documentation URLs, error page URLs, internal tool URLs — anything that enters the conversation context.
2. **URLs may be logged and retained.** Google Safe Browsing states it does not retain URLs beyond the service, but this is a policy commitment, not a technical guarantee.
3. **Metadata leakage.** Even "safe" URLs reveal what you're working on — which library docs you're reading, which error you're debugging, which API you're integrating with.
4. **URLhaus API has no authentication.** This means no user tracking on their end, but also no SLA or privacy policy you can enforce.

For most users, local feeds provide strong threat coverage with no privacy cost. Remote APIs are for users and organizations who want real-time coverage and accept the tradeoff.

## Transparency and User Override

When any tier flags a URL, the hook does **not** silently block it. Instead, it:

1. **Shows the user exactly what was flagged and why** — which tier triggered, what pattern or feed matched, what the threat category is
2. **Lets the user override** — the user sees the warning and can approve or deny the fetch

This is implemented via `permissionDecision: "ask"` rather than a hard deny. The user always has the final say. The warnings are deliberately detailed and direct — they explain the risk so the user can make an informed decision, not just click through a vague prompt.

This design reflects two principles:
- **No silent failures.** If a legitimate URL is blocked by a false positive, the user knows immediately and can proceed.
- **Informed consent over paternalism.** The hook's job is to surface risk, not to make decisions for the user.

## Architecture

The hook uses a three-tier approach. All matches surface a warning to the user.

```
URL to check
  |
  v
[Static blocklist] ----match----> WARNING + user prompt (instant, free, private)
  |
  no match
  |
  v
[Local threat feeds] --match----> WARNING + user prompt (<1ms, free, private)
  |                                (active by default, populate feeds/ with the feed updater)
  no match
  |
  v
[Remote APIs] ---------match----> WARNING + user prompt (50-500ms, privacy cost)
  |                                (opt-in via env vars)
  no match
  |
  v
  ALLOW
```

## Configuration

**Local threat feeds** are active by default. If feed files exist in `feeds/`, they are checked automatically. `checker.feedStatus()` reports whether feeds are missing or stale (older than 24 hours).

**Remote APIs** are disabled by default. Enable via config or environment variables — see `doc/design/api-surface.md` for the full configuration interface.

## Local Threat Feeds

Local feeds are the standard threat intelligence layer — active by default, no privacy cost, no API keys.

| Feed | Source | Update Frequency | Content |
|------|--------|-------------------|---------|
| URLhaus | abuse.ch | Every 5 minutes | Active malware distribution URLs |
| PhishTank | Cisco/OpenDNS | Hourly | Verified phishing URLs |
| OpenPhish | openphish.com | Every 12 hours | ML-detected phishing URLs |

Feed files are stored in `feeds/` as plain text (one URL per line) and loaded into memory at startup for O(1) lookup. The package will ship a feed updater CLI that downloads all three feeds. Run it once to populate and set up a cron job (every 30 minutes recommended) to keep feeds current. Call `checker.reload()` after an update for the running process to pick up fresh data.

Feed health is available via `checker.feedStatus()` — it reports entry counts, file age, and whether any feed is stale (older than 24 hours). See `doc/design/threat-feeds.md` for the full design.

## API Details

### URLhaus API (Primary)

```bash
curl -s --max-time 5 -X POST \
  "https://urlhaus-api.abuse.ch/v1/url/" \
  -d "url=URL_HERE"
```

- Not found: `"query_status": "no_results"`
- Found: `"query_status": "ok"` with `"threat"` field (e.g., `"malware_download"`)
- No API key required

### Google Safe Browsing Lookup API v4 (Fallback)

```bash
curl -s --max-time 5 -X POST \
  "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client": {"clientId": "agent-safety-pack", "clientVersion": "1.0"},
    "threatInfo": {
      "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      "platformTypes": ["ANY_PLATFORM"],
      "threatEntryTypes": ["URL"],
      "threatEntries": [{"url": "URL_HERE"}]
    }
  }'
```

- Safe response: `{}` (empty object)
- Unsafe response: contains `"matches"` array with `threatType`
- API key: Google Cloud Console > APIs & Services > Enable "Safe Browsing API" > Create Credentials

### DNS Blocklist (Spamhaus DBL)

```bash
# Reverse the domain and query the blocklist via DNS
RESULT=$(dig +short +time=2 "example.com.dbl.spamhaus.org" 2>/dev/null)
# NXDOMAIN (empty) = clean
# Any A record = listed (127.0.1.x = spam/malware domain)
```

- No API key, no account
- ~50ms per lookup
- Only checks domains, not full URLs
- Free for non-commercial, low-volume use
