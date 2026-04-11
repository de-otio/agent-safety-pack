// src/feeds/checker.ts
import type { LoadedFeed } from "./loader.js";

/**
 * Normalize a URL into candidate strings for feed lookup.
 *
 * Feed databases store URLs in various canonical forms; URLs arriving from the
 * agent may differ in case, encoding, query strings, fragments, default ports,
 * or dot segments. We generate multiple candidates to avoid false negatives.
 *
 * SECURITY: Without normalization, trivial evasions bypass feed lookups:
 *   - HTTPS://EVIL.COM/malware.exe (case)
 *   - https://evil.com:443/malware.exe (default port)
 *   - https://evil.com/./malware.exe (dot segment)
 *   - https://evil.com/malware%2Eexe (percent-encoding)
 */
export function normalizeForFeedLookup(url: string): string[] {
  const candidates = new Set<string>();
  candidates.add(url);

  // Basic stripping (works even for unparseable URLs)
  candidates.add(url.replace(/\/$/, ""));
  const bare = url.replace(/[?#].*$/, "").replace(/\/$/, "");
  candidates.add(bare);

  // Full canonical normalization via URL constructor
  try {
    const parsed = new URL(url);
    const scheme = parsed.protocol;
    const host = parsed.hostname.toLowerCase();

    // Strip default ports
    let port = parsed.port;
    if ((scheme === "https:" && port === "443") || (scheme === "http:" && port === "80")) {
      port = "";
    }
    const portSuffix = port ? `:${port}` : "";

    // Decode percent-encoding and resolve dot segments (URL constructor handles /../)
    let path: string;
    try {
      path = decodeURIComponent(parsed.pathname);
    } catch {
      path = parsed.pathname;
    }

    const canonical = `${scheme}//${host}${portSuffix}${path}`;
    candidates.add(canonical);
    candidates.add(canonical.replace(/\/$/, ""));

    // Also with query string for feeds that include it
    if (parsed.search) {
      candidates.add(`${canonical}${parsed.search}`);
    }
  } catch {
    // URL constructor failed — try lowercase + decode as best effort
    try {
      candidates.add(decodeURIComponent(url).toLowerCase());
    } catch {
      candidates.add(url.toLowerCase());
    }
  }

  return [...candidates];
}

export function checkFeeds(
  url: string,
  feeds: Map<string, LoadedFeed>,
): { feedName: string; description: string } | null {
  const candidates = normalizeForFeedLookup(url);
  for (const [name, feed] of feeds) {
    for (const candidate of candidates) {
      if (feed.entries.has(candidate)) {
        return { feedName: name, description: feed.description };
      }
    }
  }
  return null;
}
