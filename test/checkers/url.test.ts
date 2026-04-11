import { describe, expect, it, vi } from "vitest";
import { checkUrl } from "../../src/checkers/url.js";
import type { RemoteApiClient } from "../../src/checkers/url.js";
import type { LoadedFeed } from "../../src/feeds/loader.js";
import type { CompiledPatternSet } from "../../src/patterns/loader.js";
import type { RemoteApiResult } from "../../src/remote/urlhaus.js";

// ── helpers ──────────────────────────────────────────────────────────────────

function makeBlocklist(patterns: string[]): CompiledPatternSet {
  return {
    name: "webfetch-domain-blocklist",
    patterns: patterns.map((p) => ({ source: p, regex: new RegExp(p, "i") })),
  };
}

function makeFeeds(urlsByFeed: Record<string, string[]>): Map<string, LoadedFeed> {
  const feeds = new Map<string, LoadedFeed>();
  for (const [name, urls] of Object.entries(urlsByFeed)) {
    feeds.set(name, {
      name,
      path: `/feeds/${name}.txt`,
      entries: new Set(urls),
      entryCount: urls.length,
      modifiedAt: new Date(),
      ageSeconds: 0,
      stale: false,
      description: `${name} feed`,
    });
  }
  return feeds;
}

function makeClient(result: RemoteApiResult | null): RemoteApiClient {
  return { check: vi.fn().mockResolvedValue(result) };
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe("checkUrl — Tier 1 (blocklist)", () => {
  it("returns deny when URL matches a blocklist pattern", async () => {
    const blocklist = makeBlocklist(["\\bbit\\.ly\\b"]);
    const result = await checkUrl("https://bit.ly/abc123", blocklist, new Map(), false, [], 5000);
    expect(result.decision).toBe("deny");
    expect(result.tier).toBe("blocklist");
    expect(result.url).toBe("https://bit.ly/abc123");
  });

  it("blocklist match short-circuits (feeds and remote never called)", async () => {
    const blocklist = makeBlocklist(["\\bbit\\.ly\\b"]);
    const client = makeClient({
      source: "api:urlhaus",
      threatType: "malware",
      detail: "",
      reason: "",
    });
    const feeds = makeFeeds({ urlhaus: ["https://bit.ly/abc123"] });

    const result = await checkUrl("https://bit.ly/abc123", blocklist, feeds, true, [client], 5000);

    expect(result.tier).toBe("blocklist"); // not feed, not api
    expect(client.check).not.toHaveBeenCalled();
  });

  it("blocklist is case-insensitive", async () => {
    const blocklist = makeBlocklist(["\\bbit\\.ly\\b"]);
    const result = await checkUrl("HTTPS://BIT.LY/abc123", blocklist, new Map(), false, [], 5000);
    expect(result.decision).toBe("deny");
  });
});

describe("checkUrl — Tier 2 (local feeds)", () => {
  const emptyBlocklist = makeBlocklist([]);

  it("returns deny when URL is found in a feed", async () => {
    const feeds = makeFeeds({ urlhaus: ["https://evil.example.com/malware.exe"] });
    const result = await checkUrl(
      "https://evil.example.com/malware.exe",
      emptyBlocklist,
      feeds,
      true,
      [],
      5000,
    );
    expect(result.decision).toBe("deny");
    expect(result.tier).toBe("feed");
    expect(result.feedName).toBe("urlhaus");
  });

  it("feed match short-circuits (remote clients never called)", async () => {
    const feeds = makeFeeds({ urlhaus: ["https://evil.example.com/malware.exe"] });
    const client = makeClient({
      source: "api:urlhaus",
      threatType: "malware",
      detail: "",
      reason: "",
    });
    await checkUrl(
      "https://evil.example.com/malware.exe",
      emptyBlocklist,
      feeds,
      true,
      [client],
      5000,
    );
    expect(client.check).not.toHaveBeenCalled();
  });

  it("feed check is skipped when localFeedsEnabled=false", async () => {
    const feeds = makeFeeds({ urlhaus: ["https://evil.example.com/malware.exe"] });
    const result = await checkUrl(
      "https://evil.example.com/malware.exe",
      emptyBlocklist,
      feeds,
      false,
      [],
      5000,
    );
    expect(result.decision).toBe("allow"); // feeds disabled, no match
  });

  it("matches URL with query string against feed entry without it", async () => {
    const feeds = makeFeeds({ urlhaus: ["https://evil.example.com/malware.exe"] });
    const result = await checkUrl(
      "https://evil.example.com/malware.exe?track=spam",
      emptyBlocklist,
      feeds,
      true,
      [],
      5000,
    );
    expect(result.decision).toBe("deny");
    expect(result.tier).toBe("feed");
  });
});

describe("checkUrl — Tier 3 (remote APIs)", () => {
  const emptyBlocklist = makeBlocklist([]);

  it("returns deny when remote API flags the URL", async () => {
    const client = makeClient({
      source: "api:urlhaus",
      threatType: "malware_download",
      detail: "emotet",
      reason: "URLhaus: malware_download (emotet)",
    });
    const result = await checkUrl(
      "https://flagged.example.com/",
      emptyBlocklist,
      new Map(),
      false,
      [client],
      5000,
    );
    expect(result.decision).toBe("deny");
    expect(result.tier).toBe("api");
    expect(result.source).toBe("api:urlhaus");
    expect(result.threatType).toBe("malware_download");
    expect(result.threatDetail).toBe("emotet");
  });

  it("queries remote clients in order and short-circuits on first match", async () => {
    const client1 = makeClient({
      source: "api:urlhaus",
      threatType: "malware",
      detail: "",
      reason: "urlhaus hit",
    });
    const client2 = makeClient({
      source: "api:gsb",
      threatType: "MALWARE",
      detail: "",
      reason: "",
    });
    await checkUrl(
      "https://flagged.com/",
      emptyBlocklist,
      new Map(),
      false,
      [client1, client2],
      5000,
    );
    expect(client1.check).toHaveBeenCalled();
    expect(client2.check).not.toHaveBeenCalled(); // short-circuit
  });

  it("continues to next client when first returns null", async () => {
    const client1 = makeClient(null);
    const client2 = makeClient({
      source: "api:gsb",
      threatType: "MALWARE",
      detail: "",
      reason: "GSB hit",
    });
    const result = await checkUrl(
      "https://flagged.com/",
      emptyBlocklist,
      new Map(),
      false,
      [client1, client2],
      5000,
    );
    expect(client1.check).toHaveBeenCalled();
    expect(client2.check).toHaveBeenCalled();
    expect(result.tier).toBe("api");
    expect(result.source).toBe("api:gsb");
  });

  it("returns allow when all remote clients return null (fail open)", async () => {
    const client1 = makeClient(null);
    const client2 = makeClient(null);
    const result = await checkUrl(
      "https://safe.com/",
      emptyBlocklist,
      new Map(),
      true,
      [client1, client2],
      5000,
    );
    expect(result.decision).toBe("allow");
  });
});

describe("checkUrl — allow cases", () => {
  const emptyBlocklist = makeBlocklist([]);

  it("returns allow when nothing matches at any tier", async () => {
    const result = await checkUrl(
      "https://docs.example.com/",
      emptyBlocklist,
      new Map(),
      false,
      [],
      5000,
    );
    expect(result.decision).toBe("allow");
    expect(result.url).toBe("https://docs.example.com/");
  });

  it("returns allow for empty string input", async () => {
    const result = await checkUrl("", emptyBlocklist, new Map(), false, [], 5000);
    expect(result.decision).toBe("allow");
  });
});
