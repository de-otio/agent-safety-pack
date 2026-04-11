# Web Fetch Safety

## The Problem

AI coding agents frequently retrieve and process website content — documentation, API references, error explanations. Malicious or compromised websites can contain prompt injections or other attack vectors that attempt to manipulate the agent's behavior.

Permission prompts ("allow this fetch?") are a weak control — you cannot realistically vet every URL before the content is retrieved, and even "safe-looking" domains can serve malicious content (compromised sites, user-generated content on GitHub/Stack Overflow, etc.).

## Defense in Depth

No single control fully solves this problem. The recommended approach layers multiple defenses:

| Layer | What it does | Agent-specific? |
|-------|-------------|-----------------|
| Static blocklist patterns | Blocks known-dangerous URL categories (shorteners, paste sites, internal networks) | No — `checker.checkUrl()` |
| Local threat feeds | Checks URLs against downloaded URLhaus, PhishTank, OpenPhish databases | No — `checker.checkUrl()` |
| Remote threat APIs | Real-time checks against URLhaus API, Google Safe Browsing, Spamhaus DBL | No — `checker.checkUrl()` |
| Post-fetch injection scan | Scans fetched content for prompt injection patterns | No — `checker.checkContentInjection()` |
| Domain allowlist (permissions) | Limits the attack surface to trusted sources | Yes (Claude Code permissions) |
| Sandbox networking | OS-level enforcement even for shell-based fetches | Yes (Claude Code sandbox) |
| Model training | Inherent resistance to prompt injection | Varies by model |

The first four layers are implemented by the `@de-otio/agent-safety-pack` library and work with any agent. The last three are agent-specific features. See `doc/design/api-surface.md` for the library API and `doc/analysis/hook-safety-matrix.md` for the Claude Code integration design.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Prompt injection in fetched HTML | Post-fetch injection pattern scan + model training |
| Attacker-controlled URL construction | URL origin restriction (agent-specific) |
| Compromised trusted domains | Post-fetch content scanning + local/remote threat feeds |
| Data exfiltration via outbound fetch | Domain allowlists + sandbox networking (agent-specific) |
| Injection via shell-based curl/wget | Sandbox OS-level network restrictions (agent-specific) |
| URL shortener redirects to malicious sites | Static blocklist patterns |
| Known malware distribution URLs | Local threat feeds + remote API checks |

## Using the Safety Pack for URL Checking

### Any agent (TypeScript/Node.js)

```typescript
import { createSafetyChecker } from '@de-otio/agent-safety-pack';

const checker = createSafetyChecker();

// Check a URL before fetching
const result = await checker.checkUrl('https://bit.ly/abc123');
if (result.decision !== 'allow') {
  // result.reason explains what was flagged and why
}

// Scan fetched content for injection
const html = await fetch(url).then(r => r.text());
const scan = checker.checkContentInjection(html);
if (scan.decision !== 'allow') {
  // scan.matchedPatterns lists every pattern that fired
}
```

### Claude Code (hooks)

The Claude Code integration wires these checks into the hook system automatically. See [hook-safety-matrix.md](hook-safety-matrix.md) for the full hook architecture and configuration template.

Claude Code also supports agent-specific controls:

**Domain allowlists** — lock WebFetch to known-good domains:

```json
{
  "permissions": {
    "allow": [
      "WebFetch(domain:docs.python.org)",
      "WebFetch(domain:developer.mozilla.org)",
      "WebFetch(domain:github.com)"
    ],
    "deny": ["WebFetch"]
  }
}
```

**Disable WebFetch entirely** — when handling sensitive data:

```json
{
  "permissions": {
    "deny": ["WebFetch", "WebSearch"]
  }
}
```

## Limitations and Open Questions

- **User-generated content on trusted domains**: A GitHub issue or Stack Overflow answer on an allowed domain can still contain injection attempts. Domain allowlisting reduces but does not eliminate this risk.
- **Content-level inspection**: The post-fetch scan checks against ~100 prompt injection patterns in `injection-patterns.txt`. This catches known injection techniques but is deterministic pattern matching — novel phrasing or encoded payloads may evade it. An optional LLM-based evaluation can supplement this but is itself a prompt injection target (see [hook-safety-matrix.md](hook-safety-matrix.md), "Adapting to Evolving Threats").
- **Dynamic content**: JavaScript-rendered pages may behave differently when fetched by an agent (which typically does not execute JS) vs. viewed in a browser, potentially hiding or revealing injection payloads.
- **Agent-specific trust boundaries**: Some agents implicitly trust content from their provider's domains, which could be a target for sophisticated attackers.
