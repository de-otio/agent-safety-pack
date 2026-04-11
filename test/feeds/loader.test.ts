import { describe, it, expect, beforeEach } from 'vitest';
import { join } from 'node:path';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { loadFeeds } from '../../src/feeds/loader.js';
import { checkFeeds, normalizeForFeedLookup } from '../../src/feeds/checker.js';
import { getFeedStatus } from '../../src/feeds/status.js';

function makeFeedsDir(entries: Record<string, string[]>): string {
  const dir = join(tmpdir(), 'asp-feeds-' + Date.now() + '-' + Math.random().toString(36).slice(2));
  mkdirSync(dir, { recursive: true });
  for (const [name, urls] of Object.entries(entries)) {
    writeFileSync(join(dir, `${name}.txt`), urls.join('\n'), 'utf-8');
  }
  return dir;
}

describe('loadFeeds', () => {
  it('loads feed files into Sets', () => {
    const dir = makeFeedsDir({
      urlhaus: ['https://evil.example.com/malware.exe', 'https://bad.com/virus'],
    });
    const { feeds } = loadFeeds(dir);
    expect(feeds.has('urlhaus')).toBe(true);
    expect(feeds.get('urlhaus')?.entryCount).toBe(2);
    expect(feeds.get('urlhaus')?.entries.has('https://evil.example.com/malware.exe')).toBe(true);
  });

  it('returns empty map when feedsDir does not exist', () => {
    const { feeds, totalEntries } = loadFeeds('/nonexistent/path/feeds');
    expect(feeds.size).toBe(0);
    expect(totalEntries).toBe(0);
  });

  it('skips comment lines', () => {
    const dir = makeFeedsDir({ urlhaus: ['# comment', 'https://evil.com/'] });
    const { feeds } = loadFeeds(dir);
    expect(feeds.get('urlhaus')?.entryCount).toBe(1);
  });
});

describe('normalizeForFeedLookup', () => {
  it('returns the original URL as a candidate', () => {
    const candidates = normalizeForFeedLookup('https://evil.com/malware.exe');
    expect(candidates).toContain('https://evil.com/malware.exe');
  });

  it('strips trailing slash', () => {
    const candidates = normalizeForFeedLookup('https://evil.com/');
    expect(candidates).toContain('https://evil.com');
  });

  it('strips fragment', () => {
    const candidates = normalizeForFeedLookup('https://evil.com/page#section');
    expect(candidates).toContain('https://evil.com/page');
  });

  it('strips query string', () => {
    const candidates = normalizeForFeedLookup('https://evil.com/path?ref=tracker');
    expect(candidates).toContain('https://evil.com/path');
  });

  it('strips both query and fragment', () => {
    const candidates = normalizeForFeedLookup('https://evil.com/malware.exe?track=1#start');
    expect(candidates).toContain('https://evil.com/malware.exe');
  });

  it('normalizes case (scheme and host)', () => {
    const candidates = normalizeForFeedLookup('HTTPS://EVIL.COM/malware.exe');
    expect(candidates.some(c => c === 'https://evil.com/malware.exe')).toBe(true);
  });

  it('strips default port 443 for https', () => {
    const candidates = normalizeForFeedLookup('https://evil.com:443/malware.exe');
    expect(candidates.some(c => c === 'https://evil.com/malware.exe')).toBe(true);
  });

  it('decodes percent-encoding in path', () => {
    const candidates = normalizeForFeedLookup('https://evil.com/malware%2Eexe');
    expect(candidates.some(c => c === 'https://evil.com/malware.exe')).toBe(true);
  });
});

describe('checkFeeds', () => {
  it('returns match when URL is in a feed', () => {
    const dir = makeFeedsDir({ urlhaus: ['https://evil.example.com/malware.exe'] });
    const { feeds } = loadFeeds(dir);
    const result = checkFeeds('https://evil.example.com/malware.exe', feeds);
    expect(result).not.toBeNull();
    expect(result?.feedName).toBe('urlhaus');
  });

  it('matches URL with tracking query string against feed entry without it', () => {
    const dir = makeFeedsDir({ urlhaus: ['https://evil.example.com/malware.exe'] });
    const { feeds } = loadFeeds(dir);
    const result = checkFeeds('https://evil.example.com/malware.exe?utm_source=spam', feeds);
    expect(result).not.toBeNull();
  });

  it('returns null when URL is not in any feed', () => {
    const dir = makeFeedsDir({ urlhaus: ['https://evil.example.com/malware.exe'] });
    const { feeds } = loadFeeds(dir);
    const result = checkFeeds('https://safe.example.com/', feeds);
    expect(result).toBeNull();
  });

  it('returns null for empty feeds map', () => {
    const result = checkFeeds('https://any.com/', new Map());
    expect(result).toBeNull();
  });
});

describe('getFeedStatus', () => {
  it('returns no-feeds-dir when directory does not exist', () => {
    const status = getFeedStatus('/nonexistent', new Map());
    expect(status.status).toBe('no-feeds-dir');
  });

  it('returns no-feeds when directory exists but has no feeds', () => {
    const dir = makeFeedsDir({});
    const status = getFeedStatus(dir, new Map());
    expect(status.status).toBe('no-feeds');
  });

  it('returns ok when feeds exist and are fresh', () => {
    const dir = makeFeedsDir({ urlhaus: ['https://evil.com/'] });
    const { feeds } = loadFeeds(dir);
    const status = getFeedStatus(dir, feeds);
    expect(status.status).toBe('ok');
    expect(status.feedCount).toBe(1);
  });
});
