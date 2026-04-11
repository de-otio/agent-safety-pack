// src/remote/google-safe-browsing.ts
import type { RemoteApiResult } from "./urlhaus.js";

const THREAT_DESCRIPTIONS: Record<string, string> = {
  MALWARE: "Known malware distribution site",
  SOCIAL_ENGINEERING: "Phishing or social engineering page",
  UNWANTED_SOFTWARE: "Distributes unwanted software",
  POTENTIALLY_HARMFUL_APPLICATION: "Distributes potentially harmful applications",
};

/**
 * Check a URL against the Google Safe Browsing API v4.
 *
 * Requires a Google Cloud API key (GCP Console > APIs > Safe Browsing API > Credentials).
 * 10,000 requests/day free tier. Broadest coverage: malware, phishing, social engineering.
 *
 * SECURITY: The apiKey is embedded in the request URL inside this function only.
 * It must never be passed as a process/CLI argument where it could appear in `ps aux`.
 *
 * Returns null if the URL is clean, the check fails, or times out (fail open).
 */
export async function checkGoogleSafeBrowsing(
  url: string,
  apiKey: string,
  timeout: number,
): Promise<RemoteApiResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  // API key is constructed into the URL string here, inside the function scope only
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const body = JSON.stringify({
    client: { clientId: "agent-safety-pack", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  });

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: controller.signal,
    });

    if (!response.ok) return null;

    const data = (await response.json()) as Record<string, unknown>;

    // Empty object = clean
    if (!data.matches || !Array.isArray(data.matches) || data.matches.length === 0) {
      return null;
    }

    const match = data.matches[0] as Record<string, unknown>;
    const threatType = typeof match.threatType === "string" ? match.threatType : "UNKNOWN";
    const detail = THREAT_DESCRIPTIONS[threatType] ?? threatType;

    return {
      source: "api:google-safe-browsing",
      threatType,
      detail,
      reason: `Google Safe Browsing: ${detail}`,
    };
  } catch {
    // Timeout, network error, invalid key (4xx), parse error — fail open
    return null;
  } finally {
    clearTimeout(timer);
  }
}
