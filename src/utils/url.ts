// src/utils/url.ts

/**
 * Extracts the hostname from a URL.
 *
 * Primary path: uses the URL constructor (handles IPv6, ports, userinfo, non-HTTP schemes).
 * Fallback: manual parsing for malformed/partial URLs.
 *
 * SECURITY: The fallback must strip userinfo (user:pass@) before splitting on ':'
 * to avoid misidentifying 'user' as the host in https://user:pass@evil.com/
 */
export function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    // Fallback for malformed or partial URLs
    return (
      url
        .replace(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//, "") // strip scheme
        .replace(/^[^@]*@/, "") // strip userinfo (user:pass@)
        .split("/")[0] // strip path
        ?.split(":")[0] // strip port
        ?.split("?")[0] // strip query
        ?.split("#")[0] ?? // strip fragment
      ""
    );
  }
}

/**
 * Normalize a URL to a canonical form for pattern matching.
 *
 * SECURITY: Percent-encoding in domain names (e.g. `b%69t.ly`) bypasses
 * regex blocklist patterns. This function decodes and lowercases so
 * patterns match regardless of encoding tricks.
 *
 * For parseable URLs: lowercase scheme + host, decode path, remove default ports.
 * For unparseable URLs: attempt percent-decoding of the raw string.
 *
 * Returns an array of candidates to match against (original + normalized).
 */
export function normalizeUrlForMatching(url: string): string[] {
  const candidates = new Set<string>();
  candidates.add(url);

  // Try URL constructor for canonical normalization
  try {
    const parsed = new URL(url);
    // Lowercase scheme and host (RFC 3986: scheme and host are case-insensitive)
    const scheme = parsed.protocol; // already lowercase from URL constructor
    const host = parsed.hostname.toLowerCase();
    // Strip default ports
    let port = parsed.port;
    if ((scheme === "https:" && port === "443") || (scheme === "http:" && port === "80")) {
      port = "";
    }
    const portSuffix = port ? `:${port}` : "";
    // Decode percent-encoded path components
    const path = decodeURIComponent(parsed.pathname);
    const search = parsed.search;
    const hash = parsed.hash;
    candidates.add(`${scheme}//${host}${portSuffix}${path}${search}${hash}`);
    // Also add without query/hash for broader matching
    candidates.add(`${scheme}//${host}${portSuffix}${path}`);
  } catch {
    // URL constructor failed — try manual percent-decoding
    try {
      const decoded = decodeURIComponent(url);
      candidates.add(decoded);
      candidates.add(decoded.toLowerCase());
    } catch {
      // Double-encoded or truly malformed — add lowercase as best effort
      candidates.add(url.toLowerCase());
    }
  }

  return [...candidates];
}
