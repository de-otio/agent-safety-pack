import { afterEach, describe, expect, it } from "vitest";
import { resolveConfig } from "../src/config.js";

describe("resolveConfig", () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    // Restore env
    for (const key of [
      "AGENT_SAFETY_MODE",
      "AGENT_SAFETY_LOCAL_FEEDS",
      "AGENT_SAFETY_URLHAUS",
      "AGENT_SAFETY_GSB_KEY",
      "AGENT_SAFETY_DNSBL",
    ]) {
      delete process.env[key];
    }
    Object.assign(process.env, originalEnv);
  });

  it("returns defaults when called with no arguments", () => {
    const config = resolveConfig();
    expect(config.strict).toBe(false);
    expect(config.localFeeds).toBe(true);
    expect(config.remoteApis.urlhaus).toBe(false);
    expect(config.remoteApis.googleSafeBrowsing).toBeUndefined();
    expect(config.remoteApis.spamhausDbl).toBe(false);
    expect(config.timeouts.remoteApi).toBe(5000);
  });

  it("explicit config overrides env vars", () => {
    process.env.AGENT_SAFETY_MODE = "strict";
    const config = resolveConfig({ strict: false });
    expect(config.strict).toBe(false);
  });

  it("AGENT_SAFETY_MODE=strict enables strict mode", () => {
    process.env.AGENT_SAFETY_MODE = "strict";
    const config = resolveConfig();
    expect(config.strict).toBe(true);
  });

  it("AGENT_SAFETY_LOCAL_FEEDS=0 disables local feeds", () => {
    process.env.AGENT_SAFETY_LOCAL_FEEDS = "0";
    const config = resolveConfig();
    expect(config.localFeeds).toBe(false);
  });

  it("AGENT_SAFETY_URLHAUS=1 enables urlhaus", () => {
    process.env.AGENT_SAFETY_URLHAUS = "1";
    const config = resolveConfig();
    expect(config.remoteApis.urlhaus).toBe(true);
  });

  it("AGENT_SAFETY_GSB_KEY sets google safe browsing key", () => {
    process.env.AGENT_SAFETY_GSB_KEY = "test-key-123";
    const config = resolveConfig();
    expect(config.remoteApis.googleSafeBrowsing).toBe("test-key-123");
  });

  it("explicit remoteApis.urlhaus=false overrides env var", () => {
    process.env.AGENT_SAFETY_URLHAUS = "1";
    const config = resolveConfig({ remoteApis: { urlhaus: false } });
    expect(config.remoteApis.urlhaus).toBe(false);
  });

  it("custom patternsDir is used", () => {
    const config = resolveConfig({ patternsDir: "/custom/patterns" });
    expect(config.patternsDir).toBe("/custom/patterns");
  });

  it("feedsDir defaults adjacent to patternsDir", () => {
    const config = resolveConfig({ patternsDir: "/custom/patterns" });
    expect(config.feedsDir).toContain("feeds");
  });

  it("custom timeout is used", () => {
    const config = resolveConfig({ timeouts: { remoteApi: 3000 } });
    expect(config.timeouts.remoteApi).toBe(3000);
  });
});
