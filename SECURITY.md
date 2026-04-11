# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a bypass in the safety checks or a vulnerability that could be exploited to circumvent protections, please report it through [GitHub's private vulnerability reporting](https://github.com/de-otio/agent-safety-pack/security/advisories/new).

You can expect:
- Acknowledgment within 48 hours
- A fix or mitigation plan within 7 days for confirmed issues
- Credit in the changelog and release notes (unless you prefer anonymity)

## Scope

This project provides **defense-in-depth** pattern matching for AI coding agents. It is designed to catch common threats, not to be a comprehensive security boundary. Bypasses are expected and should be reported so the pattern databases can be improved.

In scope:
- Pattern bypasses (commands, URLs, paths, or content that should be caught but aren't)
- False negatives in threat feed checking
- Injection vulnerabilities in the check scripts themselves
- Information disclosure through error messages

Out of scope:
- Vulnerabilities in the AI agents themselves
- Issues with third-party threat feed data quality
