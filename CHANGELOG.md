# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-11

### Added

- Core TypeScript library with `createSafetyChecker()` and `createSafetyCheckerAsync()` factories
- Six curated pattern databases: bash-deny (117 patterns), secrets (76), sensitive-paths (113), domain blocklist (147), injection (101), search-leak (27)
- Three-tier URL checking pipeline: static blocklist, local threat feeds, remote APIs (URLhaus, Google Safe Browsing, Spamhaus DBL)
- Seven Claude Code hook scripts: pre-bash, pre-write, pre-read, pre-fetch, post-bash, post-fetch, post-write
- Drop-in `hooks/settings.json` for Claude Code configuration
- Feed updater CLI (`agent-safety-update-feeds`) with HTTPS-only enforcement and atomic file replacement
- Strict mode for autonomous agents (`AGENT_SAFETY_MODE=strict`)
- Environment variable overrides for all configuration options
- Dual ESM/CJS build (dist/ and dist-cjs/)
- 142 tests with 91%+ coverage

### Security

- URL normalization before blocklist matching to prevent percent-encoding bypass
- Feed lookup normalization (case, encoding, dot segments, default ports)
- Case-insensitive sensitive-path matching for macOS APFS / Windows NTFS
- DNS wildcard service SSRF protection (lvh.me, vcap.me, localtest.me, sslip.io, nip.io, xip.io)
- Fail-closed JSON parsing in all hooks (malformed input triggers deny, not allow)
- Remote API error diagnostics via `remoteErrors` field on `UrlCheckResult`
