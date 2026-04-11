import { checkFeeds } from "../feeds/checker.js";
import type { LoadedFeed } from "../feeds/loader.js";
import type { CompiledPatternSet } from "../patterns/loader.js";
import { matchFirst } from "../patterns/matcher.js";
import type { RemoteApiResult } from "../remote/urlhaus.js";
// src/checkers/url.ts
import type { UrlCheckResult } from "../types.js";
import { extractDomain } from "../utils/url.js";

export interface RemoteApiClient {
  check(url: string, domain: string, timeout: number): Promise<RemoteApiResult | null>;
}

/**
 * Check a URL through the three-tier pipeline:
 *   Tier 1: Static blocklist patterns (instant)
 *   Tier 2: Local threat feeds (instant, O(1))
 *   Tier 3: Remote APIs (50-500ms, optional, sequential)
 *
 * Each tier short-circuits on match. Remote APIs fail open.
 *
 * @param url - The URL to check
 * @param blocklistPatterns - Compiled patterns from webfetch-domain-blocklist.txt
 * @param feeds - Loaded local threat feed Sets
 * @param localFeedsEnabled - Whether to check local feeds (Tier 2)
 * @param remoteClients - Remote API clients to query in order (Tier 3)
 * @param remoteTimeout - Timeout per remote API call in ms
 */
export async function checkUrl(
  url: string,
  blocklistPatterns: CompiledPatternSet,
  feeds: Map<string, LoadedFeed>,
  localFeedsEnabled: boolean,
  remoteClients: RemoteApiClient[],
  remoteTimeout: number,
): Promise<UrlCheckResult> {
  // Input validation
  if (!url || typeof url !== "string") {
    return { decision: "allow", url: url ?? "" };
  }

  const domain = extractDomain(url);

  // Tier 1: Static blocklist
  const blocklistMatch = matchFirst(url, blocklistPatterns);
  if (blocklistMatch.matched) {
    return {
      decision: "deny",
      url,
      tier: "blocklist",
      matchedPattern: blocklistMatch.pattern,
      source: "webfetch-domain-blocklist",
      reason: `URL matches blocklist pattern: ${blocklistMatch.pattern}`,
    };
  }

  // Tier 2: Local threat feeds
  if (localFeedsEnabled) {
    const feedMatch = checkFeeds(url, feeds);
    if (feedMatch) {
      return {
        decision: "deny",
        url,
        tier: "feed",
        feedName: feedMatch.feedName,
        source: `feed:${feedMatch.feedName}`,
        reason: `URL found in ${feedMatch.description}`,
      };
    }
  }

  // Tier 3: Remote APIs (sequential, short-circuit on first match)
  for (const client of remoteClients) {
    const apiResult = await client.check(url, domain, remoteTimeout);
    if (apiResult) {
      return {
        decision: "deny",
        url,
        tier: "api",
        source: apiResult.source,
        threatType: apiResult.threatType,
        threatDetail: apiResult.detail,
        reason: apiResult.reason,
      };
    }
  }

  return { decision: "allow", url };
}
