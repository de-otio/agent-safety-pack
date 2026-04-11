import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkUrlhaus } from "../../src/remote/urlhaus.js";

describe("checkUrlhaus", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns null for a clean URL (no_results)", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ query_status: "no_results" }), { status: 200 }),
    );
    const result = await checkUrlhaus("https://safe.example.com/", 5000);
    expect(result).toBeNull();
  });

  it("returns RemoteApiResult for a flagged URL", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          query_status: "ok",
          threat: "malware_download",
          tags: ["emotet", "loader"],
        }),
        { status: 200 },
      ),
    );
    const result = await checkUrlhaus("https://evil.example.com/payload", 5000);
    expect(result).not.toBeNull();
    expect(result?.source).toBe("api:urlhaus");
    expect(result?.threatType).toBe("malware_download");
    expect(result?.detail).toContain("emotet");
  });

  it("returns null on network error (fail open)", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network error"));
    const result = await checkUrlhaus("https://example.com/", 5000);
    expect(result).toBeNull();
  });

  it("returns null on HTTP 5xx (fail open)", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("", { status: 503 }));
    const result = await checkUrlhaus("https://example.com/", 5000);
    expect(result).toBeNull();
  });

  it("returns null on malformed JSON (fail open)", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("not json", { status: 200 }));
    const result = await checkUrlhaus("https://example.com/", 5000);
    expect(result).toBeNull();
  });

  it("URL-encodes the checked URL in request body", async () => {
    let capturedBody = "";
    vi.mocked(fetch).mockImplementation(async (_url, opts) => {
      capturedBody = (opts?.body as string) ?? "";
      return new Response(JSON.stringify({ query_status: "no_results" }), { status: 200 });
    });
    await checkUrlhaus("https://example.com/path?q=1&r=2", 5000);
    expect(capturedBody).toContain("url=");
    expect(capturedBody).not.toContain("?q=1&r=2"); // should be encoded
  });
});
