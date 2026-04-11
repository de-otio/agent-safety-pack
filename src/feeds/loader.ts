// src/feeds/loader.ts
import { readFileSync, statSync, readdirSync, existsSync } from 'node:fs';
import { readFile, stat, readdir } from 'node:fs/promises';
import { join } from 'node:path';

export interface LoadedFeed {
  name: string;
  path: string;
  entries: Set<string>;
  entryCount: number;
  modifiedAt: Date;
  ageSeconds: number;
  stale: boolean;
  description: string;
}

export interface LoadedFeeds {
  feeds: Map<string, LoadedFeed>;
  totalEntries: number;
}

const FEED_DESCRIPTIONS: Record<string, string> = {
  urlhaus: 'URLhaus (abuse.ch) — active malware distribution URLs',
  phishtank: 'PhishTank (Cisco) — verified phishing URLs',
  openphish: 'OpenPhish — ML-detected phishing URLs',
};

function feedDescription(name: string): string {
  return FEED_DESCRIPTIONS[name] ?? `${name} threat feed`;
}

function buildFeed(name: string, filePath: string, content: string, mtime: Date): LoadedFeed {
  const lines = content.split('\n');
  const entries = new Set<string>();
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      entries.add(trimmed);
    }
  }
  const ageSeconds = (Date.now() - mtime.getTime()) / 1000;
  return {
    name,
    path: filePath,
    entries,
    entryCount: entries.size,
    modifiedAt: mtime,
    ageSeconds,
    stale: ageSeconds > 86400,
    description: feedDescription(name),
  };
}

export function loadFeeds(feedsDir: string): LoadedFeeds {
  const feeds = new Map<string, LoadedFeed>();
  if (!existsSync(feedsDir)) return { feeds, totalEntries: 0 };

  const files = readdirSync(feedsDir).filter(f => f.endsWith('.txt'));
  for (const file of files) {
    const filePath = join(feedsDir, file);
    const name = file.replace('.txt', '');
    try {
      const content = readFileSync(filePath, 'utf-8');
      const mtime = statSync(filePath).mtime;
      feeds.set(name, buildFeed(name, filePath, content, mtime));
    } catch {
      // Skip unreadable feed files
    }
  }

  let totalEntries = 0;
  for (const feed of feeds.values()) totalEntries += feed.entryCount;
  return { feeds, totalEntries };
}

export async function loadFeedsAsync(feedsDir: string): Promise<LoadedFeeds> {
  const feeds = new Map<string, LoadedFeed>();
  if (!existsSync(feedsDir)) return { feeds, totalEntries: 0 };

  let files: string[];
  try {
    const entries = await readdir(feedsDir);
    files = entries.filter(f => f.endsWith('.txt'));
  } catch {
    return { feeds, totalEntries: 0 };
  }

  await Promise.all(
    files.map(async file => {
      const filePath = join(feedsDir, file);
      const name = file.replace('.txt', '');
      try {
        const [content, stats] = await Promise.all([readFile(filePath, 'utf-8'), stat(filePath)]);
        feeds.set(name, buildFeed(name, filePath, content, stats.mtime));
      } catch {
        // Skip unreadable feed files
      }
    }),
  );

  let totalEntries = 0;
  for (const feed of feeds.values()) totalEntries += feed.entryCount;
  return { feeds, totalEntries };
}
