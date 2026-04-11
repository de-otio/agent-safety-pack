// src/remote/urlhaus.ts

export interface RemoteApiResult {
  source: string;
  threatType: string;
  detail: string;
  reason: string;
}

/**
 * Check a URL against the URLhaus API (abuse.ch).
 *
 * No API key required. Free, no rate limits.
 * Operated by abuse.ch, a Swiss non-profit security research project.
 *
 * Returns null if the URL is clean, the check fails, or times out (fail open).
 */
export async function checkUrlhaus(url: string, timeout: number): Promise<RemoteApiResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`,
      signal: controller.signal,
    });

    if (!response.ok) return null;

    const data = (await response.json()) as Record<string, unknown>;

    // no_results or error = clean
    if (data.query_status === "no_results" || data.query_status === "error" || !data.query_status) {
      return null;
    }

    const threat = typeof data.threat === "string" ? data.threat : "unknown";
    const tags = Array.isArray(data.tags) ? (data.tags as string[]).join(", ") : "";

    return {
      source: "api:urlhaus",
      threatType: threat,
      detail: tags,
      reason: `URLhaus: ${threat}${tags ? ` (${tags})` : ""}`,
    };
  } catch {
    // Timeout, network error, parse error — fail open
    return null;
  } finally {
    clearTimeout(timer);
  }
}
