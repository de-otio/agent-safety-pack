# Strict Mode

## Purpose

Strict mode is for autonomous agents running without a human in the loop -- backend agents on AWS AgentCore, cloud pipelines, batch processors. When no human can review a warning and make a decision, every ambiguous result must become a hard denial.

As documented in `doc/analysis/untrusted-url-use-cases.md`:

> An autonomous agent has no human to ask. If a fetch is blocked, the agent must treat it as a failed operation -- abort the current task or skip the step -- not silently continue without the data.

## Configuration

Strict mode is enabled in three ways (in order of precedence):

1. **Explicit config:** `createSafetyChecker({ strict: true })`
2. **Environment variable:** `AGENT_SAFETY_MODE=strict`
3. **Default:** `false`

```typescript
function resolveStrictMode(config: SafetyCheckerConfig): boolean {
  if (config.strict !== undefined) return config.strict;
  return process.env.AGENT_SAFETY_MODE === 'strict';
}
```

## What Changes

Strict mode affects exactly one thing: `CheckResult` objects that would have `decision: "ask"` instead have `decision: "deny"`. No other behavior changes.

| Check | Default Mode | Strict Mode |
|-------|-------------|-------------|
| `checkCommand("rm -rf /")` | `deny` | `deny` (unchanged -- already deny) |
| `checkPath(".env")` | `deny` | `deny` (unchanged -- deny section) |
| `checkPath(".github/workflows/ci.yml")` | `ask` | **`deny`** |
| `checkPath("yarn.lock")` | `ask` | **`deny`** |
| `checkUrl("https://bit.ly/abc")` | `deny` | `deny` (unchanged -- URL checks have no ask) |
| `checkContentSecrets(output)` | `deny` | `deny` (unchanged -- content checks have no ask) |
| `checkContentInjection(html)` | `deny` | `deny` (unchanged -- content checks have no ask) |

Only `checkPath` currently produces "ask" results (from the ask section of `sensitive-paths.txt`). All other checks produce either "allow" or "deny".

## Implementation

Strict mode is applied at the boundary -- in the `checkPath` method, after the pattern match but before returning the result:

```typescript
checkPath(filePath: string): PathCheckResult {
  // ... pattern matching logic ...

  if (matchResult.section === 'ask') {
    if (this.config.strict) {
      return {
        decision: 'deny',
        filePath,
        section: 'ask',
        matchedPattern: matchResult.pattern,
        source: 'sensitive-paths',
        reason: `Path matches sensitive pattern (strict mode -- ask converted to deny): ${matchResult.pattern}`,
      };
    }
    return {
      decision: 'ask',
      filePath,
      section: 'ask',
      matchedPattern: matchResult.pattern,
      source: 'sensitive-paths',
      reason: `Path matches sensitive pattern (user review recommended): ${matchResult.pattern}`,
    };
  }

  // ...
}
```

The `section` field is always set to the original section from the pattern file ("ask"), even when strict mode converts it to "deny". This allows callers to distinguish between "this path is in the hard-deny section" and "this path is in the ask section but strict mode denied it."

## How Callers Should Handle CheckResult

### Interactive Agent (strict: false)

```typescript
const result = checker.checkPath(filePath);

switch (result.decision) {
  case 'allow':
    // proceed with the operation
    break;
  case 'deny':
    // block the operation, show error to user
    break;
  case 'ask':
    // show warning to user, let them approve or deny
    // e.g. "This file is a CI config. Allow write? [y/N]"
    break;
}
```

### Autonomous Agent (strict: true)

```typescript
const result = checker.checkPath(filePath);

if (result.decision !== 'allow') {
  // Block and log. There is no 'ask' in strict mode.
  log.warn(`Safety check blocked: ${result.reason}`);
  throw new SafetyCheckError(result);
}
// proceed
```

### The CheckDecision Type

```typescript
type CheckDecision = 'allow' | 'deny' | 'ask';
```

In strict mode, the "ask" value never appears in returned results. But the type still includes it because:
1. Non-strict mode uses it.
2. The type describes the full API contract, not a specific configuration.
3. Callers who handle all three cases work correctly in both modes.

## Post-Execution Strict Mode Behavior

Content scanning methods always return `decision: "deny"` when patterns match (they have no "ask" concept). The caller decides what to do with a "deny" -- in an interactive agent, they might inject a warning; in an autonomous agent, they might discard the content.

This means the library does not need special strict-mode handling for content scanning. The decision is always "deny" or "allow". The caller's interpretation of "deny" is what changes between interactive and autonomous modes -- not the library's behavior.
