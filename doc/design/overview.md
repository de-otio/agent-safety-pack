# Overview

## Package Name

`@de-otio/agent-safety-pack`

## What This Is

A Node.js/TypeScript library that provides security and safety features for AI coding agents and agentic applications. It covers three areas:

1. **Deterministic pattern matching.** The primary defense layer. Loads pattern files from `patterns/*.txt` and applies them as compiled `RegExp` objects to validate commands, URLs, file paths, and content before and after agent tool execution. Static patterns are instant, free, and immune to prompt injection.

2. **Threat intelligence.** Local threat feeds (URLhaus, PhishTank, OpenPhish) downloaded to `feeds/` for zero-privacy-cost malware and phishing detection. Optional remote API checks (URLhaus API, Google Safe Browsing, Spamhaus DBL) for real-time coverage with a privacy tradeoff. See `doc/analysis/external-url-analysis.md` for the full URL checking architecture.

3. **LLM-based evaluation (Phase 2).** An optional supplemental layer that sends inputs to an LLM for semantic analysis — catching obfuscated exfiltration, aliased destructive commands, and novel injection patterns that static rules miss. Supports multiple LLM providers. As documented in `doc/analysis/hook-safety-matrix.md`, the LLM evaluator processes the same content an attacker crafted, so it is itself a prompt injection target. It must never be the sole defense — the deterministic layer must remain effective on its own.

The pattern files are the core value of the project. The deterministic engine is the load-bearing defense. Threat feeds and LLM evaluation are supplemental layers that extend coverage without replacing the static foundation.

## Agent Integrations

The library ships with agent-specific integration code. A user should be able to tell their agent "install the agent safety pack and help me configure it" and get a working setup.

- **Claude Code** — hook scripts shipped by the package that map `CheckResult` to Claude Code's hook protocol (`permissionDecision`, `additionalContext`, exit codes). Includes a `settings.json` template for drop-in configuration.
- **Generic** — plain scripts with simple exit codes (0 = safe, non-zero = flagged) that any agent can invoke.

Additional agent integrations can be added over time.

## Goals

1. **Complete coverage of agent tool safety.** Command checking, URL checking (three-tier pipeline: static blocklist, local feeds, remote APIs), file path checking (deny/ask sections), content scanning for injection and secrets, and strict mode for autonomous agents.

2. **Pattern files as the source of truth.** The library reads `.txt` files from `patterns/`. Pattern files are not duplicated, transpiled, or embedded as code — they are loaded from disk at runtime and compiled to `RegExp` objects once at initialization.

3. **Fast in-process matching.** All patterns are compiled to `RegExp` objects once and reused for every check. A URL check against ~130 blocklist patterns runs ~130 in-memory regex tests — no subprocess spawning, no I/O after initialization.

4. **TypeScript-first API.** Full type definitions for configuration, check results, and all public methods. Consumers get autocompletion, compile-time checking, and documentation in their editor.

5. **Strict mode as a first-class concept.** Autonomous agents (no human in the loop) need all "ask" results converted to hard denials. This is a configuration option, not an afterthought.

6. **Minimal dependencies.** The core library has zero runtime dependencies. Remote API checks use the built-in `fetch` (Node 20+). DNS blocklist checks use `node:dns`. Pattern loading uses `node:fs` and `node:path`. No frameworks, no heavy abstractions.

7. **Cross-platform.** The library targets Node.js on Linux, macOS, and Windows.

## Phased Delivery

**Phase 1 (current): Deterministic checking and threat intelligence.** Pattern matching, local threat feeds, remote API checks, strict mode, agent integrations. All goals listed above.

**Phase 2: LLM-based evaluation.** The optional supplemental layer described above. More complex to implement — it must support multiple LLM providers, handle timeouts and failures gracefully, and avoid becoming a single point of bypass via prompt injection.

## Non-Goals

1. **HTTP client or fetch proxy.** The library checks URLs and scans content. It does not fetch URLs on behalf of the caller. The caller fetches; the library inspects.

2. **Pattern authoring or management UI.** Pattern files are plain text. Edit them with a text editor.

## Key Principles

Documented in `doc/analysis/hook-safety-matrix.md`:

- **Deterministic first.** Static pattern matching is immune to prompt injection. It cannot be talked out of blocking something. The pattern files are the real defense.
- **Policy separated from mechanism.** Pattern files in `patterns/` define what to block. The library defines how to check. Either can be updated independently.
- **Transparent, not paternalistic.** Check results include the matched pattern, the source (which file or feed matched), and a human-readable reason. The caller decides what to do with the information.
- **Fail closed in strict mode.** For autonomous agents, ambiguity is denial. Every "ask" result becomes "deny" when strict mode is enabled.
