#!/usr/bin/env node
// src/bin/update-feeds.ts
import { mkdirSync, renameSync, unlinkSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

interface FeedSource {
  name: string;
  url: string;
  description: string;
}

const FEEDS: FeedSource[] = [
  {
    name: "urlhaus",
    url: "https://urlhaus.abuse.ch/downloads/text_online/",
    description: "URLhaus (abuse.ch) — active malware distribution URLs",
  },
  {
    name: "openphish",
    url: "https://openphish.com/feed.txt",
    description: "OpenPhish — ML-detected phishing URLs",
  },
];

// PhishTank source is HTTP-only — document why it's skipped
const SKIPPED_FEEDS = [
  {
    name: "phishtank",
    reason:
      "PhishTank download URL is HTTP-only (http://data.phishtank.com/...). HTTPS not available. Download manually and place at feeds/phishtank.txt.",
  },
];

async function downloadFeed(
  source: FeedSource,
  feedsDir: string,
  minEntries: number,
): Promise<boolean> {
  // Security: reject non-HTTPS source URLs
  if (!source.url.startsWith("https://")) {
    console.error(`[SKIP] ${source.name}: source URL is not HTTPS — refusing to download`);
    return false;
  }

  console.log(`[INFO] Downloading ${source.name} from ${source.url}`);

  let responseText: string;
  try {
    const response = await fetch(source.url, {
      headers: { "User-Agent": "agent-safety-pack/feed-updater" },
      signal: AbortSignal.timeout(30_000),
    });

    if (!response.ok) {
      console.error(
        `[FAIL] ${source.name}: HTTP ${response.status} ${response.statusText} — feed not replaced`,
      );
      return false;
    }

    responseText = await response.text();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[FAIL] ${source.name}: download error — ${msg} — feed not replaced`);
    return false;
  }

  // Count non-empty, non-comment lines
  const lines = responseText.split("\n").filter((l) => {
    const t = l.trim();
    return t.length > 0 && !t.startsWith("#");
  });

  if (lines.length < minEntries) {
    console.error(
      `[FAIL] ${source.name}: only ${lines.length} entries (minimum ${minEntries}) — feed not replaced`,
    );
    return false;
  }

  // Atomic replacement: write temp file in same directory as target to avoid
  // EXDEV (cross-device link) errors when feedsDir is on a different filesystem
  const livePath = join(feedsDir, `${source.name}.txt`);
  const tmpPath = join(feedsDir, `.tmp-${source.name}-${Date.now()}.txt`);

  try {
    await writeFile(tmpPath, responseText, "utf-8");
    renameSync(tmpPath, livePath);
    console.log(`[OK]   ${source.name}: ${lines.length} entries written to ${livePath}`);
    return true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[FAIL] ${source.name}: failed to write feed — ${msg}`);
    // Clean up temp file if it exists
    try {
      unlinkSync(tmpPath);
    } catch {
      /* ignore */
    }
    return false;
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      "feeds-dir": { type: "string", short: "f" },
      "min-entries": { type: "string", short: "m" },
      help: { type: "boolean", short: "h" },
    },
    allowPositionals: false,
  });

  if (values.help) {
    console.log(`
agent-safety-update-feeds — Download threat intelligence feeds for agent-safety-pack

Usage:
  agent-safety-update-feeds [options]

Options:
  -f, --feeds-dir <path>    Directory to store feed files (default: feeds/ next to package)
  -m, --min-entries <n>     Minimum entry count to accept a feed (default: 100)
  -h, --help                Show this help

Notes:
  - Only HTTPS feed sources are downloaded. HTTP sources are rejected.
  - Feeds are replaced atomically (temp file → rename).
  - The live feed is preserved if the download fails or has too few entries.
  - PhishTank is not downloaded (HTTP-only source). Place feeds/phishtank.txt manually.

Feed sources:
  urlhaus   ${FEEDS[0]?.url}
  openphish ${FEEDS[1]?.url}
`);
    process.exit(0);
  }

  const feedsDir = values["feeds-dir"]
    ? resolve(values["feeds-dir"])
    : resolve(process.cwd(), "feeds");

  const minEntries = values["min-entries"] ? Number.parseInt(values["min-entries"], 10) : 100;

  if (Number.isNaN(minEntries) || minEntries < 1) {
    console.error("[ERROR] --min-entries must be a positive integer");
    process.exit(1);
  }

  // Ensure feeds directory exists
  mkdirSync(feedsDir, { recursive: true });

  // Print info about skipped feeds
  for (const skipped of SKIPPED_FEEDS) {
    console.log(`[SKIP] ${skipped.name}: ${skipped.reason}`);
  }

  // Download all configured feeds
  const results = await Promise.all(FEEDS.map((feed) => downloadFeed(feed, feedsDir, minEntries)));

  const failed = results.filter((r) => !r).length;
  if (failed > 0) {
    console.error(
      `\n[DONE] ${results.length - failed}/${results.length} feeds updated. ${failed} failed.`,
    );
    process.exit(1);
  }

  console.log(`\n[DONE] All ${results.length} feeds updated successfully.`);
  process.exit(0);
}

main().catch((err) => {
  console.error("[FATAL]", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
