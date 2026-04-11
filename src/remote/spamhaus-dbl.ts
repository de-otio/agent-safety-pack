// src/remote/spamhaus-dbl.ts
import { promises as dns } from "node:dns";
import type { RemoteApiResult } from "./urlhaus.js";

/**
 * Check a domain against the Spamhaus DBL via DNS lookup.
 *
 * Queries <domain>.dbl.spamhaus.org for A records.
 * NXDOMAIN (no result) = clean.
 * Any A record = domain is listed.
 *
 * No API key. No account. Free for non-commercial low-volume use. ~50ms/lookup.
 * Only checks domains, not full URLs. The domain must be extracted before calling.
 *
 * Returns null if the domain is clean, not listed, or if the lookup fails (fail open).
 */
export async function checkSpamhausDbl(
  domain: string,
  timeout: number,
): Promise<RemoteApiResult | null> {
  if (!domain) return null;

  try {
    const results = await Promise.race([
      dns.resolve4(`${domain}.dbl.spamhaus.org`),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
    ]);

    if (results && results.length > 0) {
      return {
        source: "api:spamhaus-dbl",
        threatType: "Spamhaus DBL listing",
        detail: results.join(", "),
        reason: `Domain listed in Spamhaus DBL: ${results.join(", ")}`,
      };
    }

    return null;
  } catch {
    // NXDOMAIN (domain is clean), timeout, or any network error — all return null (fail open)
    return null;
  }
}
