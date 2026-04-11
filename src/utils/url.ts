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
