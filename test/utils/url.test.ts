import { describe, expect, it } from "vitest";
import { extractDomain } from "../../src/utils/url.js";

describe("extractDomain", () => {
  it("extracts hostname from a simple URL", () => {
    expect(extractDomain("https://example.com/path")).toBe("example.com");
  });

  it("handles URLs with ports", () => {
    expect(extractDomain("https://example.com:8080/path")).toBe("example.com");
  });

  it("handles URLs with query strings and fragments", () => {
    expect(extractDomain("https://docs.example.com/path?q=1#section")).toBe("docs.example.com");
  });

  it("SECURITY: handles userinfo (user:pass@host) correctly", () => {
    // Must return evil.com, not user
    expect(extractDomain("https://user:pass@evil.com/")).toBe("evil.com");
  });

  it("handles userinfo without password", () => {
    expect(extractDomain("https://user@evil.com/")).toBe("evil.com");
  });

  it("handles bare IP address URLs", () => {
    expect(extractDomain("https://192.168.1.1/path")).toBe("192.168.1.1");
  });

  it("handles subdomains", () => {
    expect(extractDomain("https://api.v2.example.com/endpoint")).toBe("api.v2.example.com");
  });

  it("handles malformed/partial URLs without throwing", () => {
    expect(() => extractDomain("not-a-url")).not.toThrow();
    expect(() => extractDomain("")).not.toThrow();
    expect(() => extractDomain("://missing-scheme")).not.toThrow();
  });

  it("handles ftp and other schemes", () => {
    expect(extractDomain("ftp://files.example.com/file.txt")).toBe("files.example.com");
  });
});
