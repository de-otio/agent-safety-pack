# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Core pattern databases: bash-deny, secrets, sensitive-paths, domain blocklist, injection patterns, search leak patterns
- Shared checking library (`lib/check.sh`) with pattern matching, threat feed checking, and external API support
- Claude Code hook integration with pre/post tool-use hooks
- Generic check scripts for any agent (`check-command`, `check-url`, `check-path`, `check-content`)
- Threat feed downloader for URLhaus, PhishTank, and OpenPhish
- Strict mode for autonomous agents (`AGENT_SAFETY_MODE=strict`)
- Optional remote API checks (URLhaus API, Google Safe Browsing, Spamhaus DBL)
