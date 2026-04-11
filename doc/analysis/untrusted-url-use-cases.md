# Untrusted URL Retrieval: Use Cases and Mitigations

Autonomous agents — backend agents running in AWS AgentCore, cloud-hosted pipelines, or any environment without a human in the loop — frequently need to fetch data from URLs they do not fully control. This document catalogs the legitimate use cases, the attack surface each creates, and how the agent-safety-pack's controls map onto them.

The core tension: you cannot eliminate untrusted URL retrieval without crippling the agent's utility. The question is not "should we allow it?" but "how do we sandbox it?"

## Legitimate Use Cases

### User-Directed Retrieval

A user (or upstream system) provides a URL and asks the agent to act on its content.

| Example | Why the URL is untrusted |
|---------|--------------------------|
| "Summarize this article: https://..." | User-supplied, could be anything |
| "Check if this endpoint is healthy" | Could point to internal infrastructure or attacker-controlled servers |
| "Parse the CSV at this S3 presigned URL" | Presigned URLs are opaque — content is whatever was uploaded |

**Risk profile:** Highest. The agent must fetch an arbitrary URL to complete the task. The user may not know (or may not care) whether the target is malicious.

### Tool Outputs Containing URLs

A tool or API returns URLs that the agent needs to follow to complete a multi-step task.

| Example | Why the URL is untrusted |
|---------|--------------------------|
| Search tool returns result URLs | Search results are attacker-influenceable (SEO poisoning) |
| API response includes pagination links | Compromised or malicious API could inject arbitrary URLs |
| Database query returns webhook/callback URLs | Stored URLs may have been injected by a prior attacker |
| JSON schema with `$ref` pointers to external files | Schema references are followed automatically by many parsers |

**Risk profile:** High. The URLs were not provided by the user — they emerged from a prior step. The agent may follow them without explicit user awareness.

### Workflow Integrations

The agent processes inbound data that naturally contains links.

| Example | Why the URL is untrusted |
|---------|--------------------------|
| Support agent parses customer-submitted tickets with links | Customer-controlled content |
| Email processing pipeline follows links in message bodies | Email is a classic phishing vector |
| RSS/Atom feed monitoring | Feed entries link to arbitrary external pages |
| Fetching documents from customer-provided storage (S3, SharePoint, GDrive) | Customer controls the content |

**Risk profile:** High. These workflows are the agent's purpose — you cannot avoid the untrusted URLs without disabling the workflow.

### Data Enrichment and Validation

The agent fetches metadata about a URL rather than consuming its full content.

| Example | Why the URL is untrusted |
|---------|--------------------------|
| Pulling OpenGraph tags for a link preview | The page controls its own OG tags |
| Checking DNS records or SSL certificate info | Lower risk — not processing page content |
| Validating that a user-submitted URL returns 200 | Minimal content processing, but still makes a network request |
| Downloading a profile image or favicon | Image parsers have their own attack surface |

**Risk profile:** Medium. The agent interacts with the URL but may not process the full response body. SSRF is still a concern.

## Attack Surface

Every use case above exposes the agent to some combination of these threats:

| Threat | Mechanism | Consequence |
|--------|-----------|-------------|
| **Prompt injection** | Fetched content contains instructions designed to hijack the agent | Agent performs attacker-chosen actions with the user's permissions |
| **SSRF** | URL points to internal services (`169.254.169.254`, `localhost`, RFC1918 ranges) | Cloud metadata exposure, internal API access, credential theft |
| **Data exfiltration** | Injected instructions trick the agent into sending context to an attacker-controlled URL | Leaks conversation history, API keys, or business data |
| **Malware delivery** | URL serves a malicious payload the agent downloads or executes | Code execution on the agent's host |
| **Resource exhaustion** | URL serves an infinite stream, a massive file, or responds with extreme latency | Agent hangs or exhausts memory/disk |
| **Redirect chains** | Short URL or 302 chain lands on a blocked destination | Bypasses URL-level blocklists if only the initial URL is checked |

## How the Agent-Safety-Pack Addresses This

The safety pack's controls map directly onto these threats. No single control is sufficient — the defense is in the layering.

### Pre-Fetch Controls (before the request is made)

| Control | Threats addressed | Implementation |
|---------|-------------------|----------------|
| **Static domain blocklist** | SSRF, redirect bypass, known-bad categories | `patterns/webfetch-domain-blocklist.txt` blocks internal networks, URL shorteners, paste sites, request catchers |
| **Local threat feeds** | Malware delivery, phishing | URLhaus, PhishTank, OpenPhish databases in `feeds/`, checked locally with zero privacy cost |
| **Remote threat APIs** | Malware delivery, phishing (real-time) | Opt-in URLhaus API, Google Safe Browsing, Spamhaus DBL — see [external-url-analysis.md](external-url-analysis.md) |
| **URL validation** | SSRF via IP literals, non-HTTP schemes | Blocklist patterns for bare IPs, `file://`, `ftp://`, `gopher://` |

### Post-Fetch Controls (after content is retrieved)

| Control | Threats addressed | Implementation |
|---------|-------------------|----------------|
| **Prompt injection scan** | Prompt injection, social engineering | `patterns/injection-patterns.txt` — ~100 patterns for instruction overrides, role manipulation, delimiter injection, encoded payloads |
| **Secret detection** | Data exfiltration (detecting leaked secrets in fetched content that could be replayed) | `patterns/secrets-patterns.txt` |

### Infrastructure-Level Controls (outside the safety pack)

These are not implemented by the safety pack but are critical for autonomous agents in production:

| Control | Threats addressed | Notes |
|---------|-------------------|-------|
| **Egress proxy** | All outbound threats | Route all agent HTTP through a proxy that enforces URL policy, logs requests, and strips sensitive headers. Essential for backend agents. |
| **Network segmentation** | SSRF | Run the agent in a network that cannot reach internal services, cloud metadata, or other sensitive endpoints. |
| **Response size/time limits** | Resource exhaustion | Enforce max response body size and connection timeout at the HTTP client or proxy level. |
| **Content-type enforcement** | Malware delivery, unexpected parsing | Only process expected content types. Reject `application/octet-stream` when expecting HTML. |
| **Output gating** | Data exfiltration, prompt injection consequences | Do not let fetched content influence actions that write to external systems without human approval or a policy check. |
| **Redirect following policy** | Redirect chain bypass | Resolve redirects at the proxy and check the final URL against blocklists, not just the initial URL. |

## Recommendations by Deployment Context

### Interactive Agent (human in the loop)

The user can see what the agent fetches and approve or deny actions. The safety pack's `permissionDecision: "ask"` model works well here — surface the risk, let the user decide.

- Enable static blocklist + local threat feeds (default)
- Enable post-fetch injection scanning (default)
- Optionally enable remote threat APIs for real-time coverage
- Use domain allowlists to limit attack surface to expected sources

### Autonomous Backend Agent (no human in the loop)

No one is watching. A prompt injection that succeeds will execute unchecked. The controls must be stricter, and **blocked fetches must be hard failures, not prompts**.

In an interactive session, a blocked URL triggers `permissionDecision: "ask"` — the human reviews the warning and decides. An autonomous agent has no human to ask. If a fetch is blocked, the agent must treat it as a failed operation — abort the current task or skip the step — not silently continue without the data, and certainly not attempt to work around the block.

The agent-safety-pack supports this via `AGENT_SAFETY_MODE=strict`. When set, every check that would normally prompt a human ("ask") becomes a hard denial instead. See [Configuring Strict Mode](#configuring-strict-mode) below.

This means:
- **Blocked URL = task failure.** The check returns a non-zero exit code. The agent's orchestrator should treat this the same as a network error or a 403 — the step did not succeed.
- **Post-fetch injection = task failure.** If fetched content triggers injection detection patterns, the post-execution hook exits non-zero. The content is discarded rather than injected into the agent's context with a "be careful" warning.
- **No retry with a different URL.** If the agent tries to re-fetch via a redirect, alternate domain, or shell-based `curl`, the same checks apply. The agent should not be able to route around the block.
- **Fail loudly.** Log the blocked URL, the reason, and the task that was aborted. This creates an audit trail and surfaces false positives for review.
- **Do not degrade gracefully into unsafe behavior.** An agent that skips a blocked fetch and proceeds with incomplete data may produce incorrect results — or worse, may be manipulable into treating the absence of data as a signal (e.g., "if the safety check fails, use this fallback URL" in an injected prompt).

Infrastructure-level requirements:
- **Mandatory:** Egress proxy with URL allowlisting — the agent should only be able to reach URLs that are necessary for its task
- **Mandatory:** Network segmentation — block access to cloud metadata, internal APIs, and other agents
- **Mandatory:** Output gating — actions triggered by fetched content (sending emails, calling APIs, writing to databases) must pass a policy check or require async human approval
- Enable all safety pack layers (static blocklist, local feeds, remote APIs, post-fetch injection scanning)
- Set response size limits and connection timeouts at the infrastructure level
- Log all fetched URLs and flag anomalies for review

### Batch/Pipeline Agent (scheduled, operates on known data sources)

The agent fetches from a known set of sources on a schedule. The URL space is more predictable.

- Use a strict URL allowlist — the agent should only fetch from its configured sources
- Blocked fetches should fail the pipeline step, not skip it — same principle as the autonomous agent above
- Enable post-fetch injection scanning even for "trusted" sources (they can be compromised)
- Monitor for new URLs appearing in the pipeline's data that were not in the original source list
- Treat any URL that does not match the allowlist as an anomaly, not just a risk

## Configuring Strict Mode

Set the `AGENT_SAFETY_MODE` environment variable to `strict` to switch from interactive to autonomous behavior:

```bash
export AGENT_SAFETY_MODE=strict
```

### What changes in strict mode

| Check | Interactive (default) | Strict |
|-------|----------------------|--------|
| **Pre-fetch: URL blocked by blocklist, feed, or API** | `permissionDecision: "ask"` — user sees warning, can override | `exit 2` — hard block, fetch denied |
| **Pre-write: path in "ask" section** (CI configs, lockfiles) | `permissionDecision: "ask"` — user decides | `exit 2` — hard block, write denied |
| **Post-fetch: injection patterns detected** | `additionalContext` warning injected — content stays in context | `exit 2` — content discarded, treated as failed fetch |
| **Post-bash: secrets in command output** | `additionalContext` warning injected | `exit 2` — output treated as error |
| **Post-write: secrets in written content** | `additionalContext` warning injected | `exit 2` — flagged as error |
| **Generic check-path: "ask" section paths** | `exit 2` (distinct from deny) | `exit 1` (same as deny) |

Checks that are already hard blocks in interactive mode (deny-section paths, bash deny patterns, search query leaks) are unchanged — they were already hard blocks.

### Using strict mode with Claude Code

Add the env var to your shell profile or pass it when launching Claude Code:

```bash
AGENT_SAFETY_MODE=strict claude
```

The session start report will show the active mode. In strict mode, no `permissionDecision: "ask"` prompts are emitted — every safety check either passes silently or blocks the action.

## Key Principle

Untrusted URL retrieval is not a bug — it is a feature that agents need to be useful. The goal is not to prevent all fetches from untrusted sources, but to ensure that:

1. **The agent cannot reach things it should not** (SSRF, internal networks)
2. **Fetched content is treated as data, not instructions** (prompt injection defense)
3. **The blast radius of a successful injection is limited** (output gating, least privilege)
4. **Someone can see what happened** (logging, transparency)

The safety pack handles concerns 1 and 2 at the tool-call level. Concerns 3 and 4 are infrastructure-level and must be addressed by the deployment environment.
