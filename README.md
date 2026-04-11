# Agent Safety Pack

`@de-otio/agent-safety-pack`

Safety guardrails for AI coding agents. Deterministic pattern matching and threat intelligence to block destructive commands, credential exposure, prompt injection, and data exfiltration — before and after agent tool execution.

Zero runtime dependencies. Node.js >= 20.

## Install

```bash
npm install @de-otio/agent-safety-pack
```

## Quick Start

```typescript
import { createSafetyChecker } from '@de-otio/agent-safety-pack';

const checker = createSafetyChecker();

// Check a shell command
const cmd = checker.checkCommand('rm -rf /');
// { decision: 'deny', matchedPattern: '...', reason: '...' }

// Check a file path
const path = checker.checkPath('.env');
// { decision: 'deny', filePath: '/abs/path/.env', section: 'deny' }

// Check a URL (async — queries local feeds + optional remote APIs)
const url = await checker.checkUrl('https://bit.ly/abc123');
// { decision: 'deny', tier: 'blocklist', url: '...' }

// Scan content for leaked secrets
const secrets = checker.checkContentSecrets('AKIA1234567890ABCDEF');
// { decision: 'deny', matchCount: 1, matchedPatterns: ['...'] }

// Scan content for prompt injection
const injection = checker.checkContentInjection(fetchedHtml);
// { decision: 'deny', matchCount: 2, matchedPatterns: ['...', '...'] }

// Check a search query for leaked sensitive data
const search = checker.checkSearchQuery('api key sk-proj-abc123');
// { decision: 'deny', matchCount: 1, matchedPatterns: ['...'] }
```

## Claude Code Integration

Copy the included hook configuration to your project's `.claude/settings.json`:

```bash
cp node_modules/@de-otio/agent-safety-pack/hooks/settings.json .claude/settings.json
```

Or merge the `hooks` section into your existing settings. This wires up 7 hooks:

| Hook | Tool | What it does |
|------|------|-------------|
| `pre-bash.js` | Bash | Blocks destructive commands, credential access, exfiltration |
| `pre-write.js` | Write/Edit/MultiEdit | Blocks writes to sensitive file paths |
| `pre-read.js` | Read/Glob/Grep | Blocks reads of sensitive file paths |
| `pre-fetch.js` | WebFetch | Blocks requests to malicious/exfiltration URLs |
| `post-bash.js` | Bash | Warns if command output contains secrets |
| `post-fetch.js` | WebFetch | Warns if fetched content contains prompt injection |
| `post-write.js` | Write/Edit/MultiEdit | Warns if written content contains secrets |

Hook protocol: `exit 2` = deny, `exit 0` + JSON = allow/ask.

## Configuration

```typescript
const checker = createSafetyChecker({
  // Custom pattern directory (default: bundled patterns/)
  patternsDir: '/path/to/patterns',
  // Custom feeds directory (default: feeds/ next to patterns)
  feedsDir: '/path/to/feeds',
  // Strict mode: all 'ask' decisions become 'deny' (default: false)
  strict: true,
  // Enable local threat feed lookups (default: true)
  localFeeds: true,
  // Remote APIs (all disabled by default)
  remoteApis: {
    urlhaus: true,                    // URLhaus API (free, no key)
    googleSafeBrowsing: 'your-key',  // Google Safe Browsing v4
    spamhausDbl: true,               // Spamhaus DBL via DNS
  },
  timeouts: {
    remoteApi: 5000, // ms per remote API call
  },
});
```

### Environment Variables

| Variable | Effect |
|----------|--------|
| `AGENT_SAFETY_MODE=strict` | Enable strict mode |
| `AGENT_SAFETY_LOCAL_FEEDS=0` | Disable local feed lookups |
| `AGENT_SAFETY_URLHAUS=1` | Enable URLhaus API |
| `AGENT_SAFETY_GSB_KEY=<key>` | Enable Google Safe Browsing with API key |
| `AGENT_SAFETY_DNSBL=1` | Enable Spamhaus DBL |

Explicit config options take precedence over environment variables.

## Pattern Databases

Six curated pattern files, compiled to RegExp at load time:

| File | Patterns | Flags | Coverage |
|------|----------|-------|----------|
| `bash-deny.txt` | 117 | `i` | Destructive ops, credential access, exfiltration, privilege escalation, supply chain, git bypasses, container escape, code obfuscation |
| `secrets-patterns.txt` | 76 | `im` | AWS, GCP, Azure, GitHub, OpenAI, Anthropic, Stripe, JWTs, PEM keys, connection strings |
| `sensitive-paths.txt` | 113 | `i` | SSH keys, cloud credentials, env files, CI/CD configs, lockfiles, IaC (deny + ask sections) |
| `webfetch-domain-blocklist.txt` | 147 | `i` | URL shorteners, paste sites, request catchers, internal networks, DNS wildcards, SSRF vectors, non-HTTP schemes |
| `injection-patterns.txt` | 101 | `im` | Instruction overrides, role manipulation, delimiter injection, hidden text, encoded payloads |
| `websearch-leak-patterns.txt` | 27 | `im` | API keys, PII, internal infrastructure in search queries |

## URL Checking Pipeline

Three-tier pipeline, sequential with short-circuit on match:

1. **Static blocklist** (instant) — regex patterns from `webfetch-domain-blocklist.txt`
2. **Local threat feeds** (instant, O(1)) — URLhaus, OpenPhish databases via `Set.has()`
3. **Remote APIs** (50-500ms, opt-in) — URLhaus API, Google Safe Browsing, Spamhaus DBL

Remote APIs are disabled by default and fail open (network errors return allow).

### Updating Threat Feeds

```bash
npx agent-safety-update-feeds --feeds-dir ./feeds
```

Downloads URLhaus and OpenPhish feeds. HTTPS-only sources. Atomic file replacement (temp file in target directory, then rename). Minimum entry count validation.

## Strict Mode

For autonomous agents with no human in the loop. All `ask` decisions become hard `deny`.

```typescript
const checker = createSafetyChecker({ strict: true });
// Or: AGENT_SAFETY_MODE=strict
```

The `section` field on `PathCheckResult` always reflects the original pattern section (`'deny'` or `'ask'`), even when strict mode converts the decision.

## API

### `createSafetyChecker(config?): SafetyChecker`

Synchronous factory. Loads all pattern files and feeds at construction time.

### `createSafetyCheckerAsync(config?): Promise<SafetyChecker>`

Async factory. Non-blocking file I/O.

### `SafetyChecker` methods

| Method | Returns | Description |
|--------|---------|-------------|
| `checkCommand(command)` | `CheckResult` | Check a shell command against bash-deny patterns |
| `checkUrl(url)` | `Promise<UrlCheckResult>` | Three-tier URL check (blocklist, feeds, remote APIs) |
| `checkPath(filePath)` | `PathCheckResult` | Check a file path against sensitive-paths (auto-resolves to absolute) |
| `checkContentSecrets(content)` | `ContentCheckResult` | Scan content for leaked secrets |
| `checkContentInjection(content)` | `ContentCheckResult` | Scan content for prompt injection |
| `checkSearchQuery(query)` | `ContentCheckResult` | Check a search query for sensitive data leaks |
| `feedStatus()` | `FeedStatus` | Get threat feed health (`ok`, `stale`, `no-feeds`, `no-feeds-dir`) |
| `reload()` | `void` | Re-read pattern files and feeds from disk |
| `reloadAsync()` | `Promise<void>` | Async reload |

### Result Types

```typescript
type CheckDecision = 'allow' | 'deny' | 'ask';

interface CheckResult {
  decision: CheckDecision;
  matchedPattern?: string;
  source?: string;
  reason?: string;
}

interface UrlCheckResult extends CheckResult {
  url: string;
  tier?: 'blocklist' | 'feed' | 'api';
  feedName?: string;
  threatType?: string;
  threatDetail?: string;
  remoteErrors?: string[];  // APIs that failed (timeout, network error)
}

interface PathCheckResult extends CheckResult {
  filePath: string;
  section?: 'deny' | 'ask';
}

interface ContentCheckResult extends CheckResult {
  matchedPatterns: string[];
  matchCount: number;
}
```

## Design Principles

**Deterministic first.** Static pattern matching is the load-bearing defense — immune to prompt injection, instant, and free.

**Policy separated from mechanism.** Pattern files in `patterns/` define what to block. The library defines how to check. Either can be updated, versioned, or audited independently.

**Transparent, not paternalistic.** Check results include the matched pattern, the source, and a human-readable reason. The caller decides what to do.

**Fail closed in strict mode.** For autonomous agents, ambiguity is denial.

## Design Documents

- [Overview](doc/design/overview.md) — Package scope, goals, phased delivery
- [Architecture](doc/design/architecture.md) — Module structure, initialization and runtime flows
- [API Surface](doc/design/api-surface.md) — Public TypeScript API contract
- [URL Checking](doc/design/url-checking.md) — Three-tier pipeline
- [Content Scanning](doc/design/content-scanning.md) — Post-execution content scanning
- [Strict Mode](doc/design/strict-mode.md) — Autonomous agent behavior
- [Pattern Loading](doc/design/pattern-loading.md) — Pattern file compilation
- [Threat Feeds](doc/design/threat-feeds.md) — Local threat feed management
- [Remote APIs](doc/design/remote-apis.md) — Remote threat intelligence services
- [Packaging](doc/design/packaging.md) — npm package structure and dual ESM/CJS build

## Requirements

- Node.js >= 20.0.0
- Platform: Linux, macOS, Windows
- Zero runtime dependencies

## License

MIT
