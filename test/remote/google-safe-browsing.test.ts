import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkGoogleSafeBrowsing } from "../../src/remote/google-safe-browsing.js";

describe("checkGoogleSafeBrowsing", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns null for a clean URL (empty response)", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }));
    const result = await checkGoogleSafeBrowsing("https://safe.example.com/", "test-key", 5000);
    expect(result).toBeNull();
  });

  it("returns null for empty matches array", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ matches: [] }), { status: 200 }),
    );
    const result = await checkGoogleSafeBrowsing("https://safe.example.com/", "test-key", 5000);
    expect(result).toBeNull();
  });

  it("returns RemoteApiResult for a MALWARE match", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({ matches: [{ threatType: "MALWARE", platformType: "ANY_PLATFORM" }] }),
        { status: 200 },
      ),
    );
    const result = await checkGoogleSafeBrowsing("https://evil.example.com/", "test-key", 5000);
    expect(result).not.toBeNull();
    expect(result?.source).toBe("api:google-safe-browsing");
    expect(result?.threatType).toBe("MALWARE");
    expect(result?.detail).toContain("malware");
  });

  it("returns RemoteApiResult for SOCIAL_ENGINEERING", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ matches: [{ threatType: "SOCIAL_ENGINEERING" }] }), {
        status: 200,
      }),
    );
    const result = await checkGoogleSafeBrowsing("https://phish.example.com/", "test-key", 5000);
    expect(result?.threatType).toBe("SOCIAL_ENGINEERING");
    expect(result?.detail).toContain("Phishing");
  });

  it("returns null on network error (fail open)", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network error"));
    const result = await checkGoogleSafeBrowsing("https://example.com/", "test-key", 5000);
    expect(result).toBeNull();
  });

  it("returns null on HTTP 400 invalid key (fail open)", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response('{"error":"invalid key"}', { status: 400 }));
    const result = await checkGoogleSafeBrowsing("https://example.com/", "bad-key", 5000);
    expect(result).toBeNull();
  });

  it("API key is embedded in the URL (not in process args)", async () => {
    let capturedUrl = "";
    vi.mocked(fetch).mockImplementation(async (url, _opts) => {
      capturedUrl = url.toString();
      return new Response(JSON.stringify({}), { status: 200 });
    });
    await checkGoogleSafeBrowsing("https://example.com/", "secret-key-xyz", 5000);
    expect(capturedUrl).toContain("secret-key-xyz");
    expect(capturedUrl).toContain("safebrowsing.googleapis.com");
  });
});
