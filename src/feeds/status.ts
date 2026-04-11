// src/feeds/status.ts
import { existsSync } from 'node:fs';
import type { FeedInfo, FeedStatus } from '../types.js';
import type { LoadedFeed } from './loader.js';

export function getFeedStatus(feedsDir: string, feeds: Map<string, LoadedFeed>): FeedStatus {
  if (!existsSync(feedsDir)) {
    return { status: 'no-feeds-dir', feedCount: 0, staleFeedCount: 0, feeds: [] };
  }

  if (feeds.size === 0) {
    return { status: 'no-feeds', feedCount: 0, staleFeedCount: 0, feeds: [] };
  }

  const feedInfos: FeedInfo[] = [];
  let staleCount = 0;

  for (const feed of feeds.values()) {
    if (feed.stale) staleCount++;
    feedInfos.push({
      name: feed.name,
      path: feed.path,
      entryCount: feed.entryCount,
      ageSeconds: feed.ageSeconds,
      stale: feed.stale,
    });
  }

  return {
    status: staleCount > 0 ? 'stale' : 'ok',
    feedCount: feeds.size,
    staleFeedCount: staleCount,
    feeds: feedInfos,
  };
}
