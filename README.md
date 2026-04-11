# Agent Safety Pack

`@de-otio/agent-safety-pack`

Security and safety features for AI coding agents and agentic applications. Provides deterministic checks — backed by curated pattern databases and local threat feeds — to block destructive commands, credential exposure, prompt injection, and data exfiltration before and after agent tool execution.

**Status: Design phase.** The TypeScript library and agent integrations are under active design. See [`doc/design/`](doc/design/) for the full specification.

## What It Will Provide

### Deterministic Pattern Matching

Compiled regex checks against six curated pattern databases:

| Pattern File | Coverage |
|-------------|----------|
| `patterns/bash-deny.txt` | ~100 patterns: destructive ops, credential access, exfiltration, privilege escalation, supply chain, git bypasses, container escape, code obfuscation |
| `patterns/secrets-patterns.txt` | ~75 patterns: AWS, GCP, Azure, GitHub, OpenAI, Anthropic, Stripe, JWTs, PEM keys, connection strings |
| `patterns/sensitive-paths.txt` | ~115 patterns: SSH keys, cloud credentials, env files, CI/CD configs, lockfiles, IaC |
| `patterns/webfetch-domain-blocklist.txt` | ~130 patterns: URL shorteners, paste sites, request catchers, internal networks, hex/decimal IP SSRF, non-HTTP schemes |
| `patterns/injection-patterns.txt` | ~100 patterns: instruction overrides, role manipulation, delimiter injection, hidden text, encoded payloads |
| `patterns/websearch-leak-patterns.txt` | ~30 patterns: API keys, PII, internal infrastructure in search queries |

### URL Threat Intelligence

Three-tier pipeline for URL safety checking:

1. **Static blocklist** — `patterns/webfetch-domain-blocklist.txt`, instant, zero privacy cost
2. **Local threat feeds** — URLhaus, PhishTank, OpenPhish databases, O(1) Set lookup, zero privacy cost
3. **Remote APIs** (opt-in) — URLhaus API, Google Safe Browsing, Spamhaus DBL, real-time but sends URLs to provider

### Agent Integrations

- **Claude Code** — hook scripts mapping `CheckResult` to Claude Code's hook protocol (`permissionDecision`, `additionalContext`)
- **Generic** — plain scripts usable from any agent

### Strict Mode

For autonomous agents with no human in the loop: all `ask` decisions become hard `deny`.

## Design Documents

### Architecture and API
- [Overview](doc/design/overview.md) — Package scope, goals, phased delivery
- [Architecture](doc/design/architecture.md) — Module structure, initialization and runtime flows
- [API Surface](doc/design/api-surface.md) — Public TypeScript API contract
- [URL Checking](doc/design/url-checking.md) — Three-tier pipeline implementation
- [Content Scanning](doc/design/content-scanning.md) — Post-execution content scanning
- [Strict Mode](doc/design/strict-mode.md) — Autonomous agent behavior
- [Pattern Loading](doc/design/pattern-loading.md) — Pattern file loading and compilation
- [Threat Feeds](doc/design/threat-feeds.md) — Local threat feed management
- [Remote APIs](doc/design/remote-apis.md) — Remote threat intelligence services
- [Packaging](doc/design/packaging.md) — npm package structure and build

### Threat Analysis
- [Safety Check Matrix](doc/analysis/hook-safety-matrix.md) — Full threat map, layered defense architecture, implementation priority
- [Web Fetch Safety](doc/analysis/web-fetch-safety.md) — URL fetch threat model, defense in depth
- [Untrusted URL Use Cases](doc/analysis/untrusted-url-use-cases.md) — Legitimate untrusted URL scenarios, attack surface, mitigations by deployment context
- [External URL Analysis](doc/analysis/external-url-analysis.md) — Threat intelligence services, local feeds vs remote APIs, privacy considerations

## Design Principles

**Deterministic first.** Static pattern matching is the load-bearing defense — immune to prompt injection, instant, and free. An optional LLM-based evaluation layer (Phase 2) supplements but never replaces it.

**Policy separated from mechanism.** Pattern files in `patterns/` define what to block. The library defines how to check. Either can be updated, versioned, or audited independently.

**Transparent, not paternalistic.** Check results include the matched pattern, the source, and a human-readable reason. The caller decides what to do — especially for URL warnings, where the user should see exactly what was flagged and why, and be able to override.

**Agent integrations included.** A user should be able to tell their agent "install the agent safety pack and configure it" and get a working setup.

**Fail closed in strict mode.** For autonomous agents, ambiguity is denial. Every `ask` becomes `deny` when strict mode is enabled.

## Requirements

- Node.js >= 20.0.0
- Platform: Linux, macOS, Windows
