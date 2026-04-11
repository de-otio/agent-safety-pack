import { afterEach, describe, expect, it, vi } from "vitest";
import { checkSpamhausDbl } from "../../src/remote/spamhaus-dbl.js";

vi.mock("node:dns", () => ({
  promises: {
    resolve4: vi.fn(),
  },
}));

describe("checkSpamhausDbl", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("returns null for a clean domain (NXDOMAIN)", async () => {
    const { promises: dnsPromises } = await import("node:dns");
    vi.mocked(dnsPromises.resolve4).mockRejectedValue(
      Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }),
    );
    const result = await checkSpamhausDbl("safe.example.com", 5000);
    expect(result).toBeNull();
  });

  it("returns RemoteApiResult for a listed domain", async () => {
    const { promises: dnsPromises } = await import("node:dns");
    vi.mocked(dnsPromises.resolve4).mockResolvedValue(["127.0.1.2"]);
    const result = await checkSpamhausDbl("spam.example.com", 5000);
    expect(result).not.toBeNull();
    expect(result?.source).toBe("api:spamhaus-dbl");
    expect(result?.threatType).toBe("Spamhaus DBL listing");
    expect(result?.detail).toContain("127.0.1.2");
  });

  it("queries the correct DNS hostname", async () => {
    const { promises: dnsPromises } = await import("node:dns");
    vi.mocked(dnsPromises.resolve4).mockRejectedValue(new Error("NXDOMAIN"));
    await checkSpamhausDbl("example.com", 5000);
    expect(vi.mocked(dnsPromises.resolve4)).toHaveBeenCalledWith("example.com.dbl.spamhaus.org");
  });

  it("returns null on DNS timeout (fail open)", async () => {
    const { promises: dnsPromises } = await import("node:dns");
    vi.mocked(dnsPromises.resolve4).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 10000, ["127.0.1.2"])),
    );
    const result = await checkSpamhausDbl("slow.example.com", 50); // 50ms timeout
    expect(result).toBeNull();
  });

  it("returns null for empty domain", async () => {
    const result = await checkSpamhausDbl("", 5000);
    expect(result).toBeNull();
  });

  it("returns null on any DNS error (fail open)", async () => {
    const { promises: dnsPromises } = await import("node:dns");
    vi.mocked(dnsPromises.resolve4).mockRejectedValue(new Error("network error"));
    const result = await checkSpamhausDbl("example.com", 5000);
    expect(result).toBeNull();
  });
});
